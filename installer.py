#!/usr/bin/env python

import os

def install(alsi):

    local_yara_support = os.path.join(alsi.alroot, 'support/yara/')

    # Build commands
    #local_yara = os.path.join(local_yara_support, 'yara-3.6.1.tar.gz')
    #alsi.fetch_package('yara-3.6.1.tar.gz', local_yara)

    # alsi.sudo_apt_install([
    #     'automake',
    #     'libtool',
    #     'make',
    #     'gcc',
    # ])

    # alsi.runcmd("cd {0}".format(local_yara_support))
    # alsi.runcmd("tar -zxf yara-3.6.1.tar.gz")
    # alsi.runcmd("cd yara-3.6.1")
    # alsi.runcmd("./bootstrap.sh")
    # alsi.runcmd("./configure --enable-dotnet")
    # alsi.runcmd("make")
    # alsi.runcmd("sudo make install")

    # Running install and statically binding libyara to yara-python. Only use dynamic-linking option if you need
    # to use libyara outside of yara-python. If you need this option, you need to build Yara standalone as shown above,
    # and run this below instead:
    # alsi.runcmd("sudo python setup.py install --dynamic-linking")

    local_yara_python = os.path.join(local_yara_support, 'yara-python-3.6.1.tar.gz')
    alsi.fetch_package('yara-python-3.6.1.tar.gz', local_yara_python)

    alsi.runcmd("cd {0}" .format(local_yara_support))
    alsi.runcmd("tar -zxf yara-python-3.6.1.tar.gz")
    alsi.runcmd("cd yara-python-3.6.1")
    alsi.runcmd("python setup.py build --enable-dotnet")
    alsi.runcmd("sudo python setup.py install")

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())

