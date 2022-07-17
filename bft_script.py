import os, os.path
import glob
import shutil
import subprocess

trial = 16
try:
    os.mkdir("logs/1_10_1ML")
except:
    pass
des_list = []
while trial <= 20:
    des_list.append(os.getcwd()+"/logs/1_10_1ML/"+str(trial))
    trial+=1
trial = 1
print (os.getcwd())
os.chdir("../hotstuff/benchmark")
print (os.getcwd())
while trial <= 5:
    os.system("fab local")
    shutil.copytree("logs", des_list[trial-1])
    trial += 1
