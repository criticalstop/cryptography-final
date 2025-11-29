import tkinter as tk
from tkinter import messagebox,filedialog
import time,random,math
root=tk.Tk()
root.title("rsa加密")
e=0
d=0
n=0

'''函数部分'''
#生成加密用的e，d和n
def genkey():
    global e,d,n
    public_key.delete(1.0,'end')
    private_key.delete(1.0,'end')
    p,q=genprime(128),genprime(128)
    phi_n=(p-1)*(q-1)
    n=p*q
    while 1:
        e=random.randint(2**(128),2**(128+1))                                                                                                                           
        if math.gcd(e,phi_n)==1:
            break
    d=getinv(e,phi_n)
    public_key.insert(1.0,str(e))
    private_key.insert(1.0,str(d))
#通过MR校验判断参数是否为素数，int n -> bool result
def isprime(n):#MR检验
    if n%2==0:
        return False
    u=n-1
    t=0
    while u%2==0:
        u//=2
        t+=1
    all=[2,325,9375,28178,450775,9780504,1795265022]#这几个费马校验数的准确率挺不错的
    for a in all: 
        v=fastExpMod(a,u,n)
        if v==1 or v==n-1:
            continue
        for i in range(1,t+1):
            v=v*v%n
            if v==n-1 and i!=t:
                v=1
                break
            if v==1:
                return False
        if v!=1:#Fermat检验
            return False
    return True
#生成素数，int keysize -> unsigned int result(2^keysize<len(result)<2^(keysize+1))
def genprime(keysize):
    while 1:
        n=random.randint(2**(keysize),2**(keysize+1))
        if isprime(n):
            return n
#扩展欧几里得除法求逆元 func(int e,int phi_n) -> int result
def getinv(e,phi_n):
    x,y,q=exgcd(e,phi_n)
    if q != 1:
        raise Exception("No solution.")
    else:
        #防止负数
        return (x+phi_n)%phi_n
def exgcd(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, q = exgcd(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, q
#在二进制字符串前补零
def addzeros(string,bits):
    while len(string)<bits:
        string='0'+string
    return string

#快速幂算法，使模平方重复计数法算幂 func(int b,int e,int m)->int b^e(mod m)
def fastExpMod(b, e, m):
    result = 1
    while e != 0:
        if (e&1) == 1:
            # ei = 1, then mul
            result = (result * b) % m
        e >>= 1
        # b, b^2, b^4, b^8, ... , b^(2^n)
        b = (b*b) % m
    return result

def encrypt():
    if n==0:
        messagebox.showerror("错误","请先生成密钥！")
        return
    starttime=time.time()
    result=''
    plaintext=plain.get(1.0,'end')[:-1]
    plaintext_encoded=plaintext.encode(encoding='GB2312')
    plaintext=''
    for i in plaintext_encoded:
        plaintext+=chr(i)
    while len(plaintext)%32!=0:
        plaintext+='\0'
    for i in range(0,len(plaintext),32):
        text_chunk=plaintext[i:i+32]
        bin_chunk=""
        for char in text_chunk:
            bin_chunk+=addzeros(bin(ord(char))[2:],8)
        int_chunk=int('0b'+bin_chunk,2)
        int_chunk_result=fastExpMod(int_chunk,e,n)
        bin_chunk_result=bin(int_chunk_result)[2:]
        bin_chunk_result=addzeros(bin_chunk_result,256+8)#为了加密中文或者文件什么的这里256位不够
        for j in range(0,len(bin_chunk_result),8):
            result+=chr(int('0b'+bin_chunk_result[j:j+8],2))
    endtime=time.time()
    time_elapsed.set("加密时间："+str(endtime-starttime)[:6]+"秒")
    cipher.delete(1.0,'end')
    cipher.insert(1.0,result)

def decrypt():
    if n==0:
        messagebox.showerror("错误","请先生成密钥！")
        return
    starttime=time.time()
    result=[]
    ciphertext=cipher.get(1.0,'end')[:-1]
    for i in range(0,len(ciphertext),33):
        text_chunk=ciphertext[i:i+33]
        bin_chunk=""
        for char in text_chunk:
            bin_chunk+=addzeros(bin(ord(char))[2:],8)
        int_chunk=int('0b'+bin_chunk,2)
        int_chunk_result=fastExpMod(int_chunk,d,n)
        bin_chunk_result=bin(int_chunk_result)[2:]
        bin_chunk_result=addzeros(bin_chunk_result,256)
        for j in range(0,len(bin_chunk_result),8):
            result.append(int('0b'+bin_chunk_result[j:j+8],2))
    result=bytes(result)
    result=result.decode(encoding='GB2312')
    endtime=time.time()
    time_elapsed.set("加密时间："+str(endtime-starttime)[:6]+"秒")
    plain.delete(1.0,'end')
    plain.insert(1.0,result)
def encrypt_file():
    if n==0:
        messagebox.showerror("错误","请先生成密钥！")
        return
    starttime=time.time()

    with open(file.get(),"rb") as fp:
        bytes=fp.read()
    while len(bytes)%32!=0:
        bytes+=b'\x00'
    
    with open(folder.get()+"/"+outname.get(),"wb") as fp:
        for i in range(0,len(bytes),32):
            byte_chunk=bytes[i:i+32]
            bin_chunk=""
            for integer in byte_chunk:
                bin_chunk+=addzeros(bin(integer)[2:],8)
            int_chunk=int('0b'+bin_chunk,2)
            int_chunk_result=fastExpMod(int_chunk,e,n)
            bin_chunk_result=bin(int_chunk_result)[2:]
            bin_chunk_result=addzeros(bin_chunk_result,256+8)#为了加密中文或者文件什么的这里256位不够
            for j in range(0,len(bin_chunk_result),8):
                fp.write(int('0b'+bin_chunk_result[j:j+8],2).to_bytes(1,'big',signed=False))
    endtime=time.time()
    time_elapsed.set("加密时间："+str(endtime-starttime)[:6]+"秒")

def decrypt_file():
    if n==0:
        messagebox.showerror("错误","请先生成密钥！")
        return
    starttime=time.time()

    with open(file.get(),"rb") as fp:
        bytes=fp.read()
    
    with open(folder.get()+"/"+outname.get(),"wb") as fp:
        for i in range(0,len(bytes),33):
            text_chunk=bytes[i:i+33]
            bin_chunk=""
            for integer in text_chunk:
                bin_chunk+=addzeros(bin(integer)[2:],8)
            int_chunk=int('0b'+bin_chunk,2)
            int_chunk_result=fastExpMod(int_chunk,d,n)
            bin_chunk_result=bin(int_chunk_result)[2:]
            bin_chunk_result=addzeros(bin_chunk_result,256)
            for j in range(0,len(bin_chunk_result),8):
                fp.write(int('0b'+bin_chunk_result[j:j+8],2).to_bytes(1,'big',signed=False))

    endtime=time.time()
    time_elapsed.set("解密时间："+str(endtime-starttime)[:6]+"秒")

'''gui部分'''
def selectfile():
    name=filedialog.askopenfilename()
    if name!='':    
        file.set(name)

def selectfolder():
    name=filedialog.askdirectory()
    if name!='':
        folder.set(name)
frame1=tk.Frame(root,padx=5,pady=5)
frame2=tk.Frame(root,padx=5,pady=5)
frame3=tk.Frame(root,padx=5,pady=5)
frame1.pack(side='left')
frame2.pack(side='left')
frame3.pack(side='left')

tk.Label(frame1,text="公钥：").pack()
public_key=tk.Text(frame1,width=30,height=10)
public_key.pack()
tk.Label(frame1,text="私钥").pack()
private_key=tk.Text(frame1,width=30,height=10)
private_key.pack()
time_elapsed=tk.StringVar()
time_elapsed.set("加/解密时间：未开始")
tk.Label(frame1,textvariable=time_elapsed).pack()
tk.Button(frame1,text="随机生成",command=genkey).pack()

tk.Label(frame2,text="明文：").pack()
plain=tk.Text(frame2,width=30,height=10)
plain.pack()
tk.Button(frame2,text="加密",anchor='e',command=encrypt).pack()
tk.Label(frame2,text="密文：").pack()
cipher=tk.Text(frame2,width=30,height=10)
cipher.pack()
tk.Button(frame2,text="解密",anchor='e',command=decrypt).pack()

tk.Label(frame3,text="待处理文件：").pack()
file=tk.StringVar()
tk.Entry(frame3,textvariable=file,width=30).pack()
tk.Button(frame3,text="选择文件",command=selectfile).pack()
tk.Label(frame3,text="输出路径：").pack()
folder=tk.StringVar()
tk.Entry(frame3,textvariable=folder,width=30).pack()
tk.Button(frame3,text="选择文件夹",command=selectfolder).pack()
tk.Label(frame3,text="输出文件名：").pack()
outname=tk.StringVar()
tk.Entry(frame3,textvariable=outname,width=30).pack()
tk.Button(frame3,text="加密文件",anchor='e',command=encrypt_file).pack()
tk.Button(frame3,text="解密文件",anchor='e',command=decrypt_file).pack()
root.mainloop()