#!/usr/bin/env python

import os

def install(alsi):

    # Config Decoder service also installs Yara, putting here:
    alsi.install_yara_3()

    # If you need to use libyara outside of yara-python, you need to build Yara separately as shown (TODO: Test):
    # local_yara_support = os.path.join(alsi.alroot, 'support/yara/')
    #
    # Build commands
    # local_yara = os.path.join(local_yara_support, 'yara-3.6.2.tar.gz')
    # alsi.fetch_package('yara-3.6.2.tar.gz', local_yara)
    #
    # alsi.sudo_apt_install([
    #     'automake',
    #     'libtool',
    #     'make',
    #     'gcc',
    # ])
    # wd = os.getcwd()
    # os.chdir(local_yara_support)
    # alsi.runcmd("tar -zxf yara-3.6.2.tar.gz")
    # os.chdir(os.path.join(local_yara_support, "yara-3.6.2"))
    # alsi.runcmd("./bootstrap.sh")
    # alsi.runcmd("./configure --enable-dotnet")
    # alsi.runcmd("make")
    # alsi.runcmd("sudo make install")
    #
    # local_yara_python = os.path.join(local_yara_support, 'yara-python-3.6.2.tar.gz')
    # alsi.fetch_package('yara-python-3.6.2.tar.gz', local_yara_python)
    #
    # os.chdir(local_yara_support)
    # alsi.runcmd("tar -zxf yara-python-3.6.2.tar.gz")
    # os.chdir(os.path.join(local_yara_support, "yara-python-3.6.2"))
    # alsi.runcmd("python setup.py build --enable-dotnet")
    # alsi.runcmd("sudo python setup.py install --dynamic-linking")
    # os.chdir(wd)

if __name__ == '__main__':
    from assemblyline.al.install import SiteInstaller
    install(SiteInstaller())

