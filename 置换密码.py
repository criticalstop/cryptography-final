import tkinter as tk
from tkinter import messagebox
import numpy as np

root=tk.Tk()
root.title("置换密码")
root.configure(bg='#001F3F')

strvars=[]
'''函数部分'''
def onehot(n,i):
    return np.eye(n)[i]
def getrules():#原理就是明文分组左乘置换规则的方阵可以变成密文
    cipherrule=[]
    for strvar in strvars:
        if int(strvar.get())>8 or int(strvar.get())<1:
            raise ValueError("超过了置换密码范围")
        cipherrule.append(int(strvar.get()))
    if len(cipherrule) != len(set(cipherrule)):
        raise ValueError("请检查转换规则是否重复")
    cipherrule=[onehot(8,i-1) for i in cipherrule]
    return np.matrix(cipherrule,dtype=np.int32)

def encrypt():
    try:
        plaintext=plain.get()
        buffer=""
        while len(plaintext)%8!=0:
            plaintext+='\0'
        for i in range(0,len(plaintext),8):
            originalmatrix=np.matrix([ord(j) for j in plaintext[i:i+8]],dtype=np.int32)
            cipheredmatrix=getrules()@originalmatrix.T
            cipheredarray=np.reshape(np.array(cipheredmatrix.T,dtype=np.int32),(8,))
            buffer+="".join([chr(j) for j in cipheredarray])
        cipher.set(buffer)
    except ValueError as e:
        if e.args[0]=="超过了置换密码范围" or e.args[0]=="请检查转换规则是否重复":
            messagebox.showerror("错误",e)
        else:
            messagebox.showerror("错误","请检查输入的规则是否不为空且为纯数字")
def decrypt():
    try:
        ciphertext=cipher.get()
        buffer=""
        #密文默认已经做完填充
        for i in range(0,len(ciphertext),8):
            originalmatrix=np.matrix([ord(j) for j in ciphertext[i:i+8]],dtype=np.int32)
            decipheredmatrix=getrules().I@originalmatrix.T#和加密不同
            decipheredarray=np.reshape(np.array(decipheredmatrix.T,dtype=np.int32),(8,))
            buffer+="".join([chr(j) for j in decipheredarray])
        plain.set(buffer)
    except ValueError as e:
        if e=="超过了置换密码范围" or e=="请检查转换规则是否重复":
            messagebox.showerror("错误",e)
        else:
            messagebox.showerror("错误","请检查输入的规则是否为纯数字")
'''gui部分'''
frame1=tk.Frame(root,padx=5,pady=5)
frame2=tk.Frame(root,padx=5,pady=5)
frame1.grid()
frame2.grid()

for i in range(0,8):
    strvars.append(tk.StringVar())
    tk.Label(frame1,text=str(i+1)).grid(row=0,column=i)
    tk.Label(frame1,text="↓").grid(row=1,column=i)
    tk.Entry(frame1,textvariable=strvars[i],width=3).grid(row=2,column=i)

plain=tk.StringVar()
tk.Label(frame2,text="明文：").grid()
tk.Entry(frame2,width=30,textvariable=plain).grid()
tk.Button(frame2,text="加密",anchor='e',pady=5,command=encrypt).grid()
cipher=tk.StringVar()
tk.Label(frame2,text="密文：").grid()
tk.Entry(frame2,width=30,textvariable=cipher).grid()
tk.Button(frame2,text="解密",anchor='e',pady=5,command=decrypt).grid()

root.mainloop()