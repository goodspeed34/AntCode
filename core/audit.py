import os
import re
from libs.config import checkExt
import json
import pathlib
from rich.table import Table
from rich.console import Console
class Audit(object):

    # 获取需要审计的目录
    def __init__(self,rootDir,ctype) -> None:
        self.rootDir = rootDir
        self.ctype = ctype
        self.checkExt = checkExt.get(ctype)
        self.getFilefree(rootDir)
        self.LoadRule()
        #rootDir = pathlib.Path.cwd()
        print(rootDir) 
    # 获取指定目录的所有文件
    def getFilefree(self,rootDir):
        fileSet = set()
        for dir_, _, files in os.walk(rootDir):
            for fileName in files:
                relDir = os.path.relpath(dir_, rootDir)
                #print(relDir)
                relFile = os.path.join(rootDir, fileName)
                filePath = self.rootDir + "/" + relFile
                #filePath = self.rootDir + "/"
                print(filePath)
                if filePath.split(".")[-1] not in self.checkExt:
                    continue
                fileSet.add(relFile)
        self.fileSet = fileSet


    # 设置对应的规则
    def LoadRule(self):
        path = os.path.split(os.path.realpath(__file__))[0] + "/../rules/"+ self.ctype 
        if os.path.exists(path):
            self.rule = json.loads(open(path,'r').read())
        else:
            print(f"[-] {self.ctype} not found!")
    # 调用对应的规则进行审计
    def checkCode(self,filePath):
        summary = []
        lineNum = 0
        with open(filePath, 'r', encoding="utf8", errors='ignore') as file:
                for line in file.readlines():
                        lineNum = lineNum + 1
                        for pattern in self.rule.keys():
                            if len(re.findall(self.rule[pattern]['regText'],line)) != 0:
                                #log = f"{filePath}:{lineNum} : {self.rule[pattern]['content']}"
                                #print(log)
                                summary.append(filePath,str(lineNum),self.rule[pattern]['content'])
                                #print(self.rule[pattern]['content'])
       return summary
                                
                                
    def Scan(self):
        console = Console()
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("文件路徑")
        table.add_column("行數")
        table.add_column("描述")
        for filepath in self.fileSet:
            for vul in self.checkCode(filepath):
                table.add_row(vul[0], vul[1], vul[2])
        console.print(table)
