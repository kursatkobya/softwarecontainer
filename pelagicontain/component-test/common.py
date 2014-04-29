#!/usr/bin/env python

"""
    Copyright (C) 2014 Pelagicore AB
    All rights reserved.
"""

import commands, os, time, sys, signal, sys
from subprocess import Popen, call, check_output, STDOUT
import os

import dbus
import dbus.service
from dbus.mainloop.glib import DBusGMainLoop

# You must initialize the gobject/dbus support for threading
# before doing anything.
import gobject
gobject.threads_init()

from dbus import glib
glib.init_threads()


class ComponentTestHelper:
    def __init__(self):
        self.__pelagicontain_pid = None
        self.__pc_iface = None
        self.__opath = "/com/pelagicore/Pelagicontain"
        self.__iface_name = "com.pelagicore.Pelagicontain"
        self.__cookie = self.generate_cookie()
        self.__app_id = "com.pelagicore.comptest"

        print "Generated Cookie = %s, appId = %s" % (self.__cookie, self.__app_id)

        self.__bus = self.create_session_bus()

        pam_remote_object = self.__bus.get_object("com.pelagicore.PAM", "/com/pelagicore/PAM")
        self.__pam_iface = dbus.Interface(pam_remote_object, "com.pelagicore.PAM")

    def create_session_bus(self):
        return dbus.SessionBus()

    def pam_iface(self):
        return self.__pam_iface

    def generate_cookie(self):
        # Only use the last part, hyphens are not allowed in D-Bus object paths
        return commands.getoutput("uuidgen").strip().split("-").pop()

    def start_pelagicontain(self, pelagicontain_bin, container_root,
            cmd="/controller/controller", suppress_stdout=False):
        """ param  pelagicontain_bin path to pelagicontain binary
            param  container_root    path to container root
            param  cmd               command to execute in container

            return true if pelagicontain started successfully
                   false otherwise
        """
        out = sys.stdout
        if (suppress_stdout):
            out = open(os.devnull, 'wb')
        try:
            self.__pelagicontain_pid = Popen([pelagicontain_bin, container_root,
                cmd, self.__cookie], stdout=out).pid
        except OSError as e:
            print "Launch error: %s" % e
            return False

        if self.__find_pelagicontain_on_dbus() == False:
            print "Could not find Pelagicontain service on D-Bus"
            return False

        return True

    def is_service_available(self):
        if self.__pc_iface is None:
            return False
        else:
            return True

    def __find_pelagicontain_on_dbus(self):
        tries = 0
        found = False

        service_name = self.__iface_name + self.__cookie
        while not found and tries < 2:
            try:
                self.__pc_object = self.__bus.get_object(service_name, self.__opath)
                self.__pc_iface = dbus.Interface(self.__pc_object, self.__iface_name)
                found = True
            except:
                pass
            time.sleep(1)
            tries = tries + 1
        if found:
            return True
        else:
            return False

    def teardown(self):
        if not self.shutdown_pelagicontain():
            if not self.__pelagicontain_pid == 0:
                call(["kill", "-9", str(self.__pelagicontain_pid)])

    def find_and_run_Launch_on_pelagicontain_on_dbus(self):
        self.__pc_iface = dbus.Interface(self.__pc_object, self.__iface_name)
        try:
            self.__pc_iface.Launch(self.__app_id)
            return True
        except Exception as e:
            print e
            return False

    def make_system_call(self, cmds):
        try:
            output = check_output(cmds)
            return (True, output)
        except:
            return (False, "")

    def shutdown_pelagicontain(self):
        if not self.__pc_iface:
            self.__find_pelagicontain_on_dbus()
            if not self.__pc_iface:
                print "Failed to find pelagicontain on D-Bus.."
                return False

        print "Shutting down Pelagicontain"
        try:
            self.__pc_iface.Shutdown()
        except dbus.DBusException as e:
            print "Pelagicontain already shutdown"
            print "D-Bus says: " + str(e)

        self.__pc_iface = None
        return True

    def pelagicontain_iface(self):
        return self.__pc_iface

    def app_id(self):
        return self.__app_id

    def cookie(self):
        return self.__cookie

