#!/usr/bin/env python

import os

def install(alsi):

    local_yara_support = os.path.join(alsi.alroot, 'support/yara/')

    # Build commands, documenting but don't think I need them?

    #local_yara = os.path.join(local_yara_support, 'yara-3.6.1.tar.gz')
    #alsi.fetch_package('yara/yara-3.6.1.tar.gz', local_yara)

    # alsi.sudo_apt_install([
    #     'automake',
    #     'libtool',
    #     'make',
    #     'gcc',
    # ])

    # alsi.runcmd("cd {0}".format(local_yara_support))
    # alsi.runcmd("tar -zxf yara-3.6.1.tar.gz")
    # alsi.runcmd("cd {0}/yara-3.6.1".format(local_yara))
    # alsi.runcmd("./bootstrap.sh")
    # alsi.runcmd("./configure --enable-dotnet")
    # alsi.runcmd("make")
    # alsi.runcmd("sudo make install")

    # Yara-Python build for no internet connection...
    # Important -- need to clone yara-python with --recursive option to get libyara:
    # git clone --recursive https://github.com/VirusTotal/yara-python (then tarball that up)
    # If there is a way to download ZIP from github with recursive library, someone let me know!

    local_yara_python = os.path.join(local_yara_support, 'yara-python.tar.gz')
    alsi.fetch_package('yara/yara-python.tar.gz', local_yara_python)

    alsi.runcmd("cd {0}".format(local_yara_support))
    alsi.runcmd("tar -zxf yara-python.tar.gz")
    alsi.runcmd("cd yara-python")
    alsi.runcmd("python setup.py build")
    # Running install and statically binding libyara to yara-python. Only use dynamic-linking option if you would need
    # to use libyara outside of yara-python. If you need this option, run this instead:
    # alsi.runcmd("sudo python setup.py install --dynamic-linking")
    alsi.runcmd("sudo python setup.py install")

    # Should just be this of you are connected to the internet.
    # TODO: TEST
    # alsi.pip_install_all([
    #     'yara-python',
    # ])

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())

