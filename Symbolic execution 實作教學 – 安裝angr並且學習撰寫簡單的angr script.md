# Symbolic execution 實作教學 – 安裝angr並且學習撰寫簡單的angr script
<h4 style="text-align:right">Wei-Ning Chen</h4>



# 實驗流程

## 安裝angr

### angr介紹
angr 是一個用於分析binary的python framework，結合靜態分析和symbolic execution 的技術，讓angr能適用於各式各樣的任務。

### 安裝dependencies

安裝angr時，由於angr所使用到的libVEX和libz3與一般使用的版本不相同，為了確保不影響本機的環境。建議使用[python virtual environment](https://virtualenvwrapper.readthedocs.io/en/latest/)


```
sudo apt-get install python-dev libffi-dev build-essential virtualenvwrapper
```
### 建立virtual environment 並安裝 angr
```
mkvirtualenv angr_lab && pip install angr
```
到這一步 就成功安裝好了 angr 在名叫 angr_lab 的virtual environment裡面

### 操作virtual environment
若要進入virtual environment
```
workon [environment name] 
```
若要退出
```
deactivate
```
更細部的操作可以參考這個[command_ref](http://virtualenvwrapper.readthedocs.io/en/latest/command_ref.html)

### 使用docker 安裝 angr
angr也能利用docker來創建一個container
```
sudo docker pull angr/angr
sudo docker run -it angr/angr
```

### angr 基本元件與使用方法



