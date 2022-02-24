import requests, re
from time import sleep
from hashlib import md5
from bs4 import BeautifulSoup as bs
from getpass import getpass

class Router:
  def __init__(self,username, password, session=requests.session(), maxUpload=150, maxDownload=8000):
    self.s = session
    self.username = username
    self.password = password    
    self.maxUpload = maxUpload
    self.maxDownload = maxDownload
    self.dict = {}
    self.macFltUrl = 'http://192.168.1.1/wlmacflt.cmd'
    self.bandCtrUrl = 'http://192.168.1.1/bondwidctr.cmd'
    self.qosList = []
    
  def login(self):
    def md5Encode(string):
      hash = md5(string.encode('utf-8')).hexdigest()
      return hash

    headers = {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.141 Safari/537.36'
    }
    data = {
      'username': md5Encode(self.username),
      'password': md5Encode(self.password),
      'sessionKey': ''
    }
    self.s.post('http://192.168.1.1/login.cgi',headers=headers, data=data)

  def addQos(self, name, startIp, endIp, upSpeed, downSpeed):
    self.qosList.append(f'{name},1,192.168.1.{startIp},{endIp},{upSpeed},{downSpeed}')
    params = (
      ('enblQos', '1'),
      ('qosList', ';'.join(self.qosList)),
      ('sessionKey', ''),
    )
    self.s.get(self.bandCtrUrl, params=params)
    
  def printQosList(self):
    for i,entry in enumerate(self.qosList):
      print(f'#{i} : {entry}')

  def deleteQos(self, index=-1):
    del self.qosList[index]
    params = (
      ('enblQos', '1'),
      ('qosList', ';'.join(self.qosList)),
      ('sessionKey', ''),
    )
    self.s.get(self.bandCtrUrl, params=params)
  
  def getMac(self, targetIp=None):
    if not self.dict:
      lan = self.s.get('http://192.168.1.1/lancfg2.html')
      soup = bs(lan.text, 'html.parser')
      script = soup.findAll('script')
      var = str(script[2]).split("var staticiplease = '")[1].split("';")[0]
      ipMACs = var.split("|")
      for ipMAC in ipMACs:
        mac = ipMAC.split("/")[0].strip().lower()
        ip = ipMAC.split("/")[1].strip()
        self.dict[ip]=mac
    return self.dict[targetIp] if targetIp else 0
  
  def printMacs(self):
    for device in self.dict:
      print(f'{device} ==> {self.dict[device]}')

  def addBlock(self, targetIp):
    params = (
      ('action', 'add'),
      ('wlFltMacAddr', self.dict[targetIp]),
      ('wlFltMacMode', 'deny'),
      ('wlSyncNvram', '1'),
      ('sessionKey', ''),
    )
    self.s.get(self.macFltUrl, params=params, allow_redirects = True)
    
  def rmBlock(self, targetIp):
    params = (
    ('action', 'remove'),
    ('rmLst', self.dict[targetIp].upper()),
    ('sessionKey', '')
    )
    self.s.get(self.macFltUrl, params=params)

  def fltMacMode(self, mode='disabled'):
    # modes : deny, disabled, allow
    params = (
    ('action', 'save'),
    ('wlFltMacMode', mode),
    ('sessionKey', '')
    )
    self.s.get(self.macFltUrl, params=params)
    
  def getQosList(self):
    src = self.s.get('http://192.168.1.1/qoscfg.html').text
    self.qosList = re.findall(r"qosList = '(.*)'", src)[0].split(";")
    
  def changePwd(self, pwd):
    params = (
    ('wl_wsc_mode', 'disabled'),
    ('wl_wsc_reg', 'enabled'),
    ('wsc_config_state', '1'),
    ('wlAuthMode', 'psk2'),
    ('wlAuth', '0'),
    ('wlWpaPsk', pwd),
    ('wlWpaGtkRekey', '3600'),
    ('wlNetReauth', '36000'),
    ('wlWep', 'disabled'),
    ('wlWpa', 'aes'),
    ('wlKeyBit', '0'),
    ('wlPreauth', '0'),
    ('wlSsidIdx', '0'),
    ('wlSyncNvram', '1'),
    ('sessionKey', '')
    )
    self.s.get('http://192.168.1.1/wlsecurity.wl', params=params)
    
  def getPwd(self):
    src = self.s.get('http://192.168.1.1/wlsecrefresh.wl').text
    pwd = re.findall(r"var wpaPskKey = '(.*)';",src)[0]
    return pwd

def main():
  user = input('Username: ')
  pwd = getpass(prompt='Password: ')
  tenda = Router(user, pwd)
  tenda.login()

  while True:
    choice = int(input('''
    [1] add QoS(Bandwidth Control) entry 
    [2] remove QoS(Bandwidth Control) entry 
    [3] Block an IP address
    [4] Remove block for an IP address
    [5] Change filter mode
    [6] Show WiFi password
    [7] Change WiFi password
    
    '''))
    if choice in [i for i in range(1,8)]:
      match choice:
        case 1:
          name = input("Enter the name: ").strip()
          startIp = input("Enter the starting IP 192.168.1.").strip()
          endIp = input("Enter the ending IP 192.168.1.").strip()
          upSpeed = input("Enter the upload speed: ").strip()
          downSpeed = input("Enter the download speed: ").strip()
          tenda.getQosList()
          tenda.addQos(name, startIp, endIp, upSpeed, downSpeed)
        case 2:
          tenda.getQosList()
          tenda.printQosList()
          index = input("Index of entry or just press Enter for last entry: ")
          tenda.deleteQos(int(index)) if index else tenda.deleteQos()
        case 3:
          tenda.getMac()
          tenda.printMacs()
          ip = int(input("Enter the IP address 192.168.1.").strip())
          ip = f'192.168.1.{ip}'
          tenda.addBlock(ip)
          sleep(2)
          tenda.fltMacMode('deny')
        case 4:
          tenda.getMac()
          tenda.printMacs()
          ip = int(input("Enter the IP address 192.168.1.").strip())
          ip = f'192.168.1.{ip}'
          tenda.rmBlock(ip)
        case 5:
          while True:
            mode = input("Which mode {disabled, allow, deny}: ").strip()
            if mode in ["disabled", "allow", "deny"]:
              tenda.fltMacMode(mode)
              break
            else:
              print('Invalid mode!')
        case 6:
          print(f'WiFi password is {tenda.getPwd()}')
        case 7:
          pwd = getpass(prompt='new WiFi password: ')
          tenda.changePwd(pwd)
    else:
      print("Invalid choice! Only integers from 1 to 6")

if __name__ == '__main__':
  main()