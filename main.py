import win32api, win32con, sys, configparser, os, wmi, ctypes,time

section_ = "proxy"
proxy_addr_ = "127.0.0.1"
proxy_port_ = 9666
proxy_override_ = [
    "*.csdn.net", "127.0.0.1", "192.168.*", "www.jianshu.com", "*.baidu.*",
    "*.cn", "localhost"
]

proxy_pro_ = "U1804.exe"


def kill_ie():
    c = wmi.WMI()
    kernel32 = ctypes.windll.kernel32
    for process in c.Win32_Process():
        if process.Name == 'iexplore.exe':
            kernel32.TerminateProcess(
                kernel32.OpenProcess(1, 0, process.ProcessId), 0)

def config_proxy_pro():
    with open("u.ini", 'a') as configfile:
        cfg = configparser.ConfigParser()
        cfg.read("u.ini")
        _section="Options"
        if not cfg.has_section(_section):
            cfg.add_section(_section)
            cfg.set(_section, 'ConnectMode', str(0))
            cfg.set(_section, 'EnableShare', str(1))
            cfg.set(_section, 'LocalPort', str(9666))
            cfg.set(_section, 'UseHotKeys', str(1))
            cfg.set(_section, 'NotUseIE', str(1))
            cfg.set(_section, 'AutoStartIE', str(0))
            cfg.set(_section, 'ClearCookie', str(0))
            cfg.set(_section, 'ClearHistory', str(0))
            cfg.set(_section, 'QuickCloseIE', str(0))
            cfg.set(_section, 'NotCloseIE', str(1))
            cfg.set(_section, 'HideGoldLock', str(0))
            cfg.set(_section, 'ProxyMode', str(2))
            cfg.set(_section, 'HideGoldLock', str(0))
            cfg.set(_section, 'ProxyHost', str(0))
            cfg.set(_section, 'ProxyPort', str(0))
            cfg.set(_section, 'AutoStartChrome', str(0))
            cfg.set(_section, 'NotCloseChrome', str(1))
            cfg.set(_section, 'HideWindows', str(1))
            cfg.write(configfile)
            return False
    return True


def changeIEProxy(keyName, keyValue):
    pathInReg = 'Software\Microsoft\Windows\CurrentVersion\Internet Settings'
    key = win32api.RegOpenKey(win32con.HKEY_CURRENT_USER, pathInReg, 0,
                              win32con.KEY_ALL_ACCESS)
    win32api.RegSetValueEx(key, keyName, 0, win32con.REG_SZ, keyValue)
    win32api.RegCloseKey(key)


def check_config():
    with open("config.ini", 'a') as configfile:
        cfg = configparser.ConfigParser()
        cfg.read("config.ini")
        if not cfg.has_section(section_):
            cfg.add_section(section_)
            proxy_addr = proxy_addr_ + ":" + str(proxy_port_)
            proxy_override = ";".join(proxy_override_)
            cfg.set('proxy', 'ProxyServer', proxy_addr)
            cfg.set('proxy', 'ProxyOverride', proxy_override)
            cfg.set('proxy', 'ProxyPro', proxy_pro_)
            cfg.write(configfile)
            return False
    return True


if __name__ == "__main__":
    _section = sys.argv[1] if len(sys.argv) > 1 else section_
    check_config()
    kill_ie()
    config = configparser.ConfigParser()
    config.read('config.ini')
    if config.has_section(_section):
        config_proxy_pro()
        _ProxyPro = config.get(_section, "ProxyPro")
        win32api.ShellExecute(0, 'open', _ProxyPro, '', '', 0)
        time.sleep(2)
        _ProxyServer = config.get(_section, 'ProxyServer')
        _ProxyOverride = config.get(_section, 'ProxyOverride')

        changeIEProxy('ProxyEnable', str(1))
        changeIEProxy('ProxyServer', _ProxyServer)
        changeIEProxy('ProxyOverride', _ProxyOverride)
        print('Proxy has been successfully seted,url:' + _ProxyServer)
