# -*- coding:utf-8 -*-
import idautils
import idaapi
import idc
from datetime import datetime

def gethalstead():
    funcs=[xxx] #想要计算的函数,如果想要计算main函数，可以写成funcs=['main']
    total_halstead=0
    for func_name in funcs:
        #获取函数开始地址
        start_addr = idc.LocByName(func_name)  
        #获取函数结束地址
        end_addr= idc.FindFuncEnd(start_addr)  
        #print("func_name={},start_addr={},end_addr={}".format(func_name,hex(start_addr),hex(end_addr)))
        #read_ins为待处理指令，它从函数开始地址开始
        read_ins=start_addr   
        #用于存放操作符，为字典类型，键为操作符，值为操作符个数
        ins_dict={}  
        #用于存储操作数个数，为字典类型，键为操作符，值为操作数个数
        opnd_dict={} 
        # 待处理指令一直获取，直到到达函数结束地址 
        while read_ins != end_addr:    
	    #获取当前指令的助记符
            ins_char=idc.GetMnem(read_ins)  
	    #当前指令的第一个操作数，若没有则为空
            opnd_num0= idc.GetOpnd(read_ins,0)   
	    #当前指令的第二个操作数，若没有则为空
            opnd_num1= idc.GetOpnd(read_ins,1)   
            #print("ins_char={},ins_num0={},ins_num1={}".format(ins_char,opnd_num0,opnd_num1))
	    #将ins_char添加/更新ins_dict中
            if ins_char not in ins_dict:  
                ins_dict[ins_char]=1
            else:
                ins_dict[ins_char]+=1
	    #将ins_char添加/更新opnd_dict中
            if ins_char not in opnd_dict:  
                if opnd_num0 != "" and opnd_num1 != "":
                    opnd_dict[ins_char]=2
                elif opnd_num0 == "" and opnd_num1 == "":
                    opnd_dict[ins_char]=0
                else:
                    opnd_dict[ins_char]=1
            elif ins_char in opnd_dict:
                if opnd_num0 != "" and opnd_num1 != "":
                    opnd_dict[ins_char]+=2
                elif opnd_num0 == "" and opnd_num1 == "":
                    opnd_dict[ins_char]+=0
                else:
                    opnd_dict[ins_char]+=1
        
            read_ins=idc.NextHead(read_ins)  #读取下一条指令
        t1=len(ins_dict)
        t2=0
        t3=0
        for i in ins_dict:
            t2+=ins_dict[i]
            t3+=opnd_dict[i]
        #对ins_dict进行排序
        ins_dict_sorted=sorted(ins_dict.items(),key=lambda d: d[1], reverse=True) 
        #输出
        print(func_name)
        print('[Mnemonic]           [Frequency]         [OperandNum]')
        print('----------           -----------         -------------')
        print("T:{:<10d}         T:{:<11d}       T:{:<12d}".format(t1,t2,t3))
        print('----------           -----------         -------------')
        for j in range(len(ins_dict_sorted)):
            print("{:<10}           {:<11d}          {:<12d}".format(ins_dict_sorted[j][0],ins_dict_sorted[j][1],opnd_dict[ins_dict_sorted[j][0]]))
    
        halstead=t2+t3
    
        print("halstead:{:<10d}".format(halstead))
        total_halstead+=halstead
        print('\n')
    
    print("total_halstead:",total_halstead)

class HalsteadMetric(idaapi.plugin_t):  # 继承 idaapi.plugin_t
    """
    插件类
    """
    flags = idaapi.PLUGIN_UNL
    comment = "get halstead metric of functions"

    wanted_name = "HalsteadMetric"  # 插件的名称，在IDA界面导航栏中显示 Edit->Plugins->HalsteadMetric
    wanted_hotkey = "Alt-F6"  # 插件的快捷键
    help = "Coming soon..."


    def init(self): 
        """
        初始化方法
        """
	idaapi.msg(">>>Halstead_Metric v1.0 2022 - WYF \n\n")

        return idaapi.PLUGIN_OK  # return PLUGIN_KEEP
    
    def run(self, arg):
	gethalstead()
	
    
    def term(self):
	pass
	
        

def PLUGIN_ENTRY():
    """
    实例化插件对象
    """
    return HalsteadMetric()

