#! /usr/bin/env python3
# -*- coding: utf-8 -*-
import requests,json,socket,sys,time
import os
from cmdrun import run,_decode_data,push_wechat_group
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import datetime
Token=''
ids=[]

#需要配置的地方
########################################################################################################################
#ARL持续监控，把ARL侦察到的资产导入nuclei进行漏洞扫描，实现对目标资产持续监控，持续扫描，漏洞通知
arl_url='https://127.0.0.1:5003/'
username='admin'
password='MWH05265513'
time_sleep=3600# 秒为单位，获取资产
get_size=100   # 每次获取任务数，不用改


webhook_url='https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=ce0a1152-26e3-46d6-a2b0-b6808b7414b7'  #漏洞结果，企业微信漏洞通知key

########################################################################################################################

# 间隔1h无限循环
while True:
    try:
        push_wechat_group('~# 开始新的扫描，即将侦察新增资产_')
        data = {"username":username,"password":password}
        headers = {'Content-Type': 'application/json; charset=UTF-8'}
        logreq=requests.post(url=arl_url+'/api/user/login',data=json.dumps(data),headers=headers,timeout=30, verify=False)
        result = json.loads(logreq.content.decode())
        if result['code']==401:
            print(data,'登录失败')
            sys.exit()
        if result['code']==200:
            print(data, '登录成功',result['data']['token'])
            Token=result['data']['token']
        headers = {'Token': Token,'Content-Type': 'application/json; charset=UTF-8'}
        print('开始获取最近侦察资产')
        req =requests.get(url=arl_url+'/api/task/?page=1&size='+str(get_size), headers=headers,timeout=30, verify=False)
        result = json.loads(req.content.decode())
        for xxx in result['items']:
            if xxx['status']=='done':
                ids.append(xxx['_id'])
        ids=str(ids).replace('\'','"')
        ids_result = json.loads(ids)
        data = {"task_id":ids_result}
        req2=requests.post(url=arl_url+'/api/batch_export/site/',data=json.dumps(data),headers=headers,timeout=30, verify=False)
        if '"not login"' in str(req2.text):
            ids = []
            continue
        target_list=req2.text.split()
        file_list=open('./caches/cache.txt','r',encoding='utf-8').read().split('\n')
        add_list=set(file_list).symmetric_difference(set(target_list))
        #current_time=str(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')).replace(' ','-').replace(':','-')
        if len(add_list):
            for xxxx in add_list:
                if xxxx in target_list:
                    caches_file=open('./caches/cache.txt', 'a', encoding='utf-8')
                    caches_file.write(xxxx+'\n')
                    caches_file.close()
                    with open (r"./txt/domains.txt", 'a', encoding='utf-8') as f:
                        f.write(xxxx + "\n")
                    # get_log=open('./get_log/'+current_time+'.txt','a', encoding='utf-8')
                    # get_log.write(xxxx+'\n')
                    # get_log.close()
            count = len ( open (r'./txt/domains.txt', 'r').readlines ())
            push_wechat_group('~# 资产侦察完毕，新增资产' + str(count) +'个,开始漏洞扫描_')
            
            # nuclei漏洞扫描,通知
            run(r'./nuclei/nuclei -l ./txt/domains.txt -mhe 10 -ni -o res-all-vulnerability-results.txt -nc -silent -severity critical,medium,high')
            os.system(r'rm ./txt/domains.txt')
            os.system(r'rm ./res-all-vulnerability-results.txt')
            #xray
            
            push_wechat_group('~# 本次扫描结束，即将休眠1小时_')
            time.sleep(int(time_sleep))
            Token = ''
            ids = []
        else:
            push_wechat_group('~# 未有新增资产，即将休眠1小时_')
            time.sleep(int(time_sleep))
            Token = ''
            ids = []

    except Exception as e:
        print(e,'出错了，请排查')