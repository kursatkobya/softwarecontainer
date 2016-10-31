/*
 * Copyright (C) 2016 Pelagicore AB
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR
 * BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 * For further information see LICENSE
 */


#include <cstring>
#include "ifaddrs.h"
#include "unistd.h"
#include "networkgateway.h"
#include "generators.h"

#include <netdb.h>

NetworkGateway::NetworkGateway() :
    Gateway(ID),
    m_internetAccess(false),
    m_interfaceInitialized(false)
{
}

NetworkGateway::~NetworkGateway()
{
}

ReturnCode NetworkGateway::readConfigElement(const json_t *element)
{
    IPTableEntry e;
    if (!read(element, "type", e.type)) {
        log_error() << "No type specified in network config.";
        return ReturnCode::FAILURE;
    }

    if (e.type != "INCOMING" && e.type != "OUTGOING") {
        log_error() << e.type << " is not a valid type ('INCOMING' or 'OUTGOING')";
        return ReturnCode::FAILURE;
    }

    int p;
    if (!read(element, "priority", p)) {
      log_error() << "No priority specified in network config.";
      return ReturnCode::FAILURE;
    }
    e.priority = p;

    if (e.priority < 1) {
        log_error() << "Priority can not be less than 1 but is " << e.priority;
        return ReturnCode::FAILURE;
    }

    const json_t *rules = json_object_get(element, "rules");

    if (rules == nullptr) {
        log_error() << "No rules specified";
        return ReturnCode::FAILURE;
    }

    if (!json_is_array(rules)) {
        log_error() << "Rules not specified as an array";
        return ReturnCode::FAILURE;
    }

    size_t ix;
    json_t *val;
    json_array_foreach(rules, ix, val) {
        if (json_is_object(val)) {
            if (isError(parseRule(val, e.m_rules))) {
                log_error() << "Could not parse rule config";
                return ReturnCode::FAILURE;
            }
        } else {
            log_error() << "formatting of rules array is incorrect.";
            return ReturnCode::FAILURE;
        }
    }

    std::string readTarget;
    if (!read(element, "default", readTarget)) {
        log_error() << "No default target specified or default target is not a string.";
        return ReturnCode::FAILURE;
    }

    if (parseTarget(readTarget)) {
        e.defaultTarget = readTarget;
    } else {
        log_error() << "Default target '" << readTarget << "' is not a supported target.Invalid target.";
        return ReturnCode::FAILURE;
    }

    m_entries.push_back(e);

    // --- TEMPORARY WORKAROUND ---
    // in the wait of activate() being rewritten
    if ("ACCEPT" == e.defaultTarget) {
        m_internetAccess = true;
        m_gateway = "10.0.3.1";
    }
    // ----------------------------
    return ReturnCode::SUCCESS;
}

ReturnCode NetworkGateway::parseRule(const json_t *element, std::vector<IPTableEntry::Rule> &rules)
{
    IPTableEntry::Rule r;
    std::string target;
    if (!read(element, "target", target)) {
        log_error() << "Target not specified in the network config";
        return ReturnCode::FAILURE;
    }

    if (parseTarget(target)) {
        r.target = target;
    } else {
        log_error() << target << " is not a valid target.";
        return ReturnCode::FAILURE;
    }

    std::string host;
    if (!read(element, "host", host)) {
        log_error() << "Host not specified in the network config.";
        return ReturnCode::FAILURE;
    }

    if (ReturnCode::FAILURE == parseHost(host, r.host)) {
        log_error() << host << "is not valid host";
        return ReturnCode::FAILURE;
    }

    // Parsing different port formats
    json_t *port = json_object_get(element, "port");
    if (port != nullptr) {
        parsePort(port, r.ports);
    }
    // If there were no port configured, leave the port list empty
    // and assume that all ports should be considered in the rule.

    rules.push_back(r);
    return ReturnCode::SUCCESS;
}

ReturnCode NetworkGateway::parseHost(const std::string hostname, IPTableEntry::Host &host)
{
    auto pos = hostname.find("/");
    auto s_ipaddr = hostname.substr(0, pos);
    auto s_mask = hostname.substr(pos+1, hostname.size());

    if (inet_pton(AF_INET, s_ipaddr.c_str(), &host.hostIP.s_addr)) {
        // its ip address
        log_debug() << "its hostname " << s_ipaddr << ":" << host.hostIP.s_addr << " " << s_mask;
        host.hostMask.s_addr = (0xFFFFFFFF << (32 - std::stoi(s_mask))) & 0xFFFFFFFF;
        return ReturnCode::SUCCESS;
    }

    //its hostname
    auto converter = gethostbyname(s_ipaddr.c_str());
    memcpy(&host.hostIP.s_addr, converter->h_addr_list[0], converter->h_length);
    log_debug() << "its ipaddr " << s_ipaddr << "host.hostIP.s_addr:" << host.hostIP.s_addr;
    host.hostMask.s_addr = 0xFFFFFFFF;

    return ReturnCode::SUCCESS;
}

ReturnCode NetworkGateway::parsePort(const json_t *element, std::vector<unsigned int> &ports)
{
    // Port formatted as single integer
    if (json_is_integer(element)) {
        int port = json_integer_value(element);
        ports.push_back(port);

    // Port formatted as a string representing a range
    } else if (json_is_string(element)) {
        std::string portRange = json_string_value(element);

        const std::string::size_type n = portRange.find("-");
        const std::string first = portRange.substr(0, n);
        const std::string last = portRange.substr(n + 1);

        int startPort;
        if (!parseInt(first.c_str(), &startPort)) {
             log_error() << "Starting port in range " << portRange << "is not an integer.";
             return ReturnCode::FAILURE;
        }

        int endPort;
        if (!parseInt(first.c_str(), &endPort)) {
             log_error() << "End port in range " << portRange << "is not an integer.";
             return ReturnCode::FAILURE;
        }

        for (int i = startPort; i <= endPort; ++i) {
            ports.push_back(i);
        }

    // Port formatted as a list of integers
    } else if (json_is_array(element)) {
        size_t ix;
        json_t *val;
        json_array_foreach(element, ix, val) {
            if (!json_is_integer(val)) {
                log_error() << "Entry in port array is not an integer.";
                return ReturnCode::FAILURE;
            }

            int port = json_integer_value(element);
            ports.push_back(port);
        }
    } else {
        log_error() << "Rules specified in an invalid format";
        return ReturnCode::FAILURE;
    }
    return ReturnCode::SUCCESS;
}

bool NetworkGateway::parseTarget(const std::string &str)
{
    if (str == "ACCEPT" || str == "DROP" || str == "REJECT") {
        return true;
    }
    return false;
}

bool NetworkGateway::activateGateway()
{
    if (!hasContainer()) {
        log_error() << "activate was called on an EnvironmentGateway which has no associated container";
        return false;
    }

    if (m_gateway.size() != 0) {
        log_debug() << "Default gateway set to " << m_gateway;
    } else {
        m_internetAccess = false;
        log_debug() << "No gateway. Network access will be disabled";
    }

    if ( !isBridgeAvailable() ) {
        log_error() << "Bridge not available, expected gateway to be " << m_gateway;
        return false;
    }

    if (m_internetAccess) {
        generateIP();
        log_debug() << "Trying to apply rules";
        for (auto entry:m_entries) {
            entry.applyRules();
        }
        return up();
    } else {
        return down();
    }
}

bool NetworkGateway::teardownGateway()
{
    return true;
}

const std::string NetworkGateway::ip()
{
    return m_ip;
}

bool NetworkGateway::generateIP()
{
    log_debug() << "Generating ip-address";
    const char *ipAddrNet = m_gateway.substr(0, m_gateway.size() - 1).c_str();

    m_ip = m_generator.gen_ip_addr(ipAddrNet);
    log_debug() << "IP set to " << m_ip;

    return true;
}

bool NetworkGateway::setDefaultGateway()
{
    ReturnCode ret = executeInContainer([this] {
        Netlink n;
        ReturnCode success = n.setDefaultGateway(m_gateway.c_str());
        return isSuccess(success) ? 0 : 1;
    });

    return isSuccess(ret);
}

bool NetworkGateway::up()
{
    if (m_interfaceInitialized) {
        log_debug() << "Interface already configured";
        return true;
    }

    log_debug() << "Attempting to bring up eth0";
    ReturnCode ret = executeInContainer([this] {
        Netlink n;

        Netlink::LinkInfo iface;
        if (isError(n.findLink("eth0", iface))) {
            log_error() << "Could not find interface eth0 in container";
            return 1;
        }

        int ifaceIndex = iface.first.ifi_index;
        if (isError(n.linkUp(ifaceIndex))) {
            log_error() << "Could not bring interface eth0 up in container";
            return 2;
        }

        in_addr ip_addr;
        inet_aton(ip().c_str(), &ip_addr);
        return isSuccess(n.setIP(ifaceIndex, ip_addr, 24)) ? 0 : 3;
    });

    if (isSuccess(ret)) {
        m_interfaceInitialized = true;
        return setDefaultGateway();
    } else {
        log_debug() << "Failed to bring up eth0";
        return false;
    }
}

bool NetworkGateway::down()
{
    log_debug() << "Attempting to configure eth0 to 'down state'";
    ReturnCode ret = executeInContainer([this] {
        Netlink n;
        Netlink::LinkInfo iface;
        if (isError(n.findLink("eth0", iface))) {
            log_error() << "Could not find interface eth0 in container";
            return 1;
        }

        if (isError(n.linkDown(iface.first.ifi_index))) {
            log_error() << "Could not bring interface eth0 down in container";
            return 2;
        }

        return 0;
    });

    if (isError(ret)) {
        log_error() << "Configuring eth0 to 'down state' failed.";
        return false;
    }

    return true;
}

bool NetworkGateway::isBridgeAvailable()
{
    Netlink::LinkInfo iface;
    if (isError(m_netlinkHost.findLink(BRIDGE_DEVICE, iface))) {
        log_error() << "Could not find " << BRIDGE_DEVICE << " in the host";
    }

    std::vector<Netlink::AddressInfo> addresses;
    if (isError(m_netlinkHost.findAddresses(iface.first.ifi_index, addresses))) {
        log_error() << "Could not fetch addresses for " << BRIDGE_DEVICE << " in the host";
    }

    return isSuccess(m_netlinkHost.hasAddress(addresses, AF_INET, m_gateway.c_str()));
}

std::string IPTableEntry::getChain() {
    if ( "INCOMING" == type) {
        return "INPUT";
    } else if ("OUTGOING" == type) {
        return "OUTPUT";
    } else if ("FORWARD" == type) {
        return "FORWARD";
    }
    return "";
}

bool IPTableEntry::applyRules()
{
    struct xtc_handle *handle;

    handle = iptc_init ("filter");

    if (!handle) {
        log_error() << "Could not init IPTC library ";
        return false;
    }

    for (auto rule:m_rules) {
        if (!insertRule(rule, getChain(), handle)) {
            log_error() << "Couldn't apply the rule " << rule.target;
        }
    }

    if (!iptc_commit (handle))
    {
        log_error() <<  "Could not commit changes in iptables " << iptc_strerror (errno);
        return true;
    }


    iptc_free(handle);
    return true;
}

#if true

bool IPTableEntry::insertRule(Rule rule, std::string type, struct xtc_handle *handle)
{
    struct _entry
    {
        _entry () {
            memset(this, 0, sizeof(_entry));
            this->target.target.u.user.target_size = XT_ALIGN(sizeof(struct xt_standard_target));
            this->entry.target_offset = XT_ALIGN(sizeof(struct ipt_entry)) +
                    XT_ALIGN(sizeof(struct ipt_entry_match)) + XT_ALIGN(sizeof(struct ipt_tcp));
            this->entry.next_offset = this->entry.target_offset + this->target.target.u.user.target_size;
        };

        struct ipt_entry entry;
        struct ipt_entry_match match_proto;
        struct ipt_tcp tcpinfo;
        struct xt_standard_target target;
    } entry;

    strncpy(entry.target.target.u.user.name
            , rule.target.c_str()
            , sizeof (entry.target.target.u.user.name));

    log_debug() << "IP:" << rule.host.hostIP.s_addr << " mask:" << rule.host.hostMask.s_addr << " target:" <<
                rule.target << " entry target:" << entry.target.target.u.user.name;

     entry.entry.ip.src.s_addr = rule.host.hostIP.s_addr;
     entry.entry.ip.smsk.s_addr = rule.host.hostMask.s_addr;

     entry.match_proto.u.match_size = sizeof(struct ipt_entry_match) + sizeof(struct ipt_tcp);
     strcpy(entry.match_proto.u.user.name, "tcp");

     if (rule.ports.empty()) {
        if (!iptc_append_entry (type.c_str(), &entry.entry, handle)) {
            log_error() << "Could not insert a rule in iptables " << iptc_strerror (errno);
            return false;
        }
     } else {
         for (auto port:rule.ports) {
             entry.tcpinfo.spts[0] = 0;
             entry.tcpinfo.spts[1] = ntohs(port);
             if (!iptc_append_entry (type.c_str(), &entry.entry, handle)) {
                 log_error() << "Could not add port filter "
                             << port << " in iptables "
                             << iptc_strerror (errno);
                 return false;
             }
         }
     }

    return true;
}

#else

bool IPTableEntry::insertRule(Rule rule, std::string type, struct xtc_handle *handle)
{
    struct ipt_entry * e;
    struct ipt_entry_match * match_proto, * match_limit, * match_physdev;
    struct ipt_entry_target * target;
    struct ipt_tcp * tcpinfo;
    struct xt_rateinfo * rateinfo;
    struct xt_physdev_info * physdevinfo;
    unsigned int size_ipt_entry, size_ipt_entry_match, size_ipt_entry_target, size_ipt_tcp, size_rateinfo, size_physdevinfo, total_length;

    size_ipt_entry = XT_ALIGN(sizeof(struct ipt_entry));
    size_ipt_entry_match = XT_ALIGN(sizeof(struct ipt_entry_match));
    size_ipt_entry_target = XT_ALIGN(sizeof(struct ipt_entry_target));
    size_ipt_tcp = XT_ALIGN(sizeof(struct ipt_tcp));
    size_rateinfo = XT_ALIGN(sizeof(struct xt_rateinfo));
    size_physdevinfo = XT_ALIGN(sizeof(struct xt_physdev_info));
    total_length =  size_ipt_entry + size_ipt_entry_match * 3 + size_ipt_entry_target + size_ipt_tcp + size_rateinfo + size_physdevinfo;

    //memory allocation for all structs that represent the netfilter rule we want to insert
    e = (struct ipt_entry *) calloc(1, total_length);
    //offsets to the other bits:
    //target struct begining
    e->target_offset = size_ipt_entry + size_ipt_entry_match * 3 + size_ipt_tcp + size_rateinfo + size_physdevinfo;
    //next "e" struct, end of the current one
    e->next_offset = total_length;

    //  Filter IP
    e->ip.src.s_addr     = rule.host.hostIP.s_addr;
    e->ip.smsk.s_addr    = rule.host.hostMask.s_addr;
    e->ip.proto          = IPPROTO_TCP;



    //match structs setting:
    //set match rule for the protocol to use
    //”-p tcp” part of our desirable rule
    match_proto = (struct ipt_entry_match *) e->elems;
    match_proto->u.match_size = size_ipt_entry_match + size_ipt_tcp;
    strcpy(match_proto->u.user.name, "tcp");//set name of the module, we will use in this match

    //set match rule for the packet number per time limitation - against DoS attacks
    //”-m limit” part of our desirable rule
    match_limit = (struct ipt_entry_match *) (e->elems + match_proto->u.match_size);
    match_limit->u.match_size = size_ipt_entry_match + size_rateinfo;
    strcpy(match_limit->u.user.name, "limit");//set name of the module, we will use in this match

    //set match rule for specific Ethernet card (interface)
    //”-m physdev” part of our desirable rule
    match_physdev = (struct ipt_entry_match *) (e->elems + match_proto->u.match_size + match_limit->u.match_size);
    match_physdev->u.match_size = size_ipt_entry_match + size_physdevinfo;
    strcpy(match_physdev->u.user.name, "physdev");//set name of the module, we will use in this match

    //tcp module - match extension
    //”--sport 0:59136 --dport 0:51201” part of our desirable rule
    tcpinfo = (struct ipt_tcp *)match_proto->data;

    //limit module - match extension
    //”-limit 2000/s --limit-burst 10” part of our desirable rule
    rateinfo = (struct xt_rateinfo *)match_limit->data;
    rateinfo->avg = 5;
    rateinfo->burst = 10;

    //physdev module - match extension
    //”-in eth0” part of our desirable rule
    physdevinfo = (struct xt_physdev_info *)match_physdev->data;
    strcpy(physdevinfo->physindev, "eth0");
    physdevinfo->bitmask = 1;


    //target struct
    target = (struct ipt_entry_target *)(e->elems + size_ipt_entry_match * 3 + size_ipt_tcp + size_rateinfo + size_physdevinfo);
    target->u.target_size = size_ipt_entry_target;
    strcpy(target->u.user.name, rule.target.c_str());


    if (rule.ports.empty()) {
        if (!iptc_append_entry (type.c_str(), e, handle)) {
            log_error() << "Could not insert a rule in iptables " << iptc_strerror (errno);
            return false;
        }
    } else {
        for (auto port:rule.ports) {
            tcpinfo->spts[0] = ntohs(port);
            tcpinfo->spts[1] = ntohs(port);

            if (!iptc_append_entry (type.c_str(), e, handle)) {
                log_error() << "Could not add port filter "
                        << port << " in iptables "
                        << iptc_strerror (errno);
                return false;
            }
        }
    }


    return true;
}
#endif
