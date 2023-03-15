import subprocess
import sys
import requests

# 微信推送漏洞信息
def push_wechat_group(content):
    global webhook_url
    try:
        # print('开始推送')
        resp = requests.post(webhook_url,
                             json={"msgtype": "markdown",
                                   "markdown": {"content": content}})
        print(content)
        if 'invalid webhook url' in str(resp.text):
            print('企业微信key 无效,无法正常推送')
            sys.exit()
        if resp.json()["errcode"] != 0:
            raise ValueError("push wechat group failed, %s" % resp.text)
    except Exception as e:
        print(e)

def run(cmd, shell=True):
    """
    开启子进程，执行对应指令，控制台打印执行过程，然后返回子进程执行的状态码和执行返回的数据
    :param cmd: 子进程命令
    :param shell: 是否开启shell
    :return: 子进程状态码和执行结果
    """
    n = 1
    print('\033[1;32m************** START **************\033[0m')
    p = subprocess.Popen(cmd, shell=shell, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    while p.poll() is None:
        line = p.stdout.readline().strip()
        if line:
            line = _decode_data(line)
            if "weak-cipher-suites" in line and "ssl" in line:
                n=n+1
            elif "put-method-enabled" in line:
                n=n+1
            elif "insecure-firebase-database" in line:
                n=n+1
            elif "CVE-2017-5487" in line:
                n=n+1
            elif "CVE-2022-24681" in line:
                n=n+1
            elif "joomla-manifest-file" in line:
                n=n+1
            elif "CVE-2022-1595" in line:
                n=n+1
            elif "kanboard-default-login" in line:
                n=n+1
            elif "CVE-2019-3403" in line:
                n=n+1
            elif "CVE-2022-40083" in line:
                n=n+1
            elif "firebase-config-exposure" in line:
                n=n+1
            elif "CVE-2023-24044" in line:
                n=n+1
            elif "appspec-yml-disclosure" in line:
                n=n+1
            else:
                push_wechat_group('~# 疑似漏洞！！！请立即验证~\n~# 以下为漏洞详情：\n' + line)
        # 清空缓存
        sys.stdout.flush()
        sys.stderr.flush()
    return


def _decode_data(byte_data: bytes):
    """
    解码数据
    :param byte_data: 待解码数据
    :return: 解码字符串
    """
    try:
        return byte_data.decode('UTF-8')
    except UnicodeDecodeError:
        return byte_data.decode('GB18030')


# if __name__ == '__main__':
#     run('./nuclei -u hackerone.com -mhe 10 -ni -o res-all-vulnerability-results.txt -stats -silent -severity critical,medium,high,low')