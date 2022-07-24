import os, os.path
import glob
import shutil
import subprocess

trial = 1
try:
    os.mkdir("logs/1_10_1ML_50_50")
except:
    pass
des_list = []
while trial <= 20:
    des_list.append(os.getcwd()+"/logs/1_10_1ML_50_50/"+str(trial))
    trial+=1
trial = 1
print (os.getcwd())
os.chdir("../hotstuff/benchmark")
print (os.getcwd())
while trial <= 20:
    os.system("fab local")
    shutil.copytree("logs", des_list[trial-1])
    trial += 1
