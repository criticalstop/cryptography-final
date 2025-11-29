import tkinter as tk
from tkinter import messagebox

root=tk.Tk()
root.title("替代密码")
root.configure(bg='#001F3F')

rules={}#明文找密文
rules_rev={}#密文找明文
'''函数部分'''
def compute_rules():
    global rules
    rules.clear()
    rules_rev.clear()
    cipherkey=key.get()[:26]
    convertrules.delete("1.0","end")
    if not cipherkey.isalpha():
        messagebox.showerror("错误","不接受除了英文字符以外的密钥！")
        raise Exception("密钥错误")
    cipherkey=list(cipherkey.upper())
    if len(cipherkey)!=len(set(cipherkey)):
        messagebox.showerror("错误","密钥中有重复的字符！")
        raise Exception("密钥错误")
    for i in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if i not in cipherkey:
            cipherkey.append(i)
    for i in range(0,26):
        rules[chr(65+i)]=cipherkey[i]
        rules_rev[cipherkey[i]]=chr(65+i)
    convertrules.configure(state="normal")
    for i in list(rules.items()):
        convertrules.insert(tk.INSERT,i[0]+"->"+i[1]+' ')
    convertrules.configure(state="disabled")

def encrypt():
    try:
        compute_rules()
    except Exception:
        return
    
    plaintext=plain.get().upper()
    if not plaintext.isalpha():
        messagebox.showerror("错误","明文为空或不接受除了英文字符以外的明文！")
        return

    ciphertext="".join([rules[i] for i in plaintext])
    cipher.set(ciphertext)

def decrypt():
    try:
        compute_rules()
    except Exception("密钥错误"):
        return
    
    ciphertext=cipher.get().upper()
    if not ciphertext.isalpha():
        messagebox.showerror("错误","密文为空或不接受除了英文字符以外的密文！")
        return
    
    plaintext="".join([rules_rev[i] for i in ciphertext])
    plain.set(plaintext)

'''gui 部分'''
frame1=tk.Frame(root)#这里放了密钥
frame2=tk.Frame(root)#这里放了置换的规则
frame3=tk.Frame(root)#这里放了置换的文字
frame1.pack(side='left',padx=5,pady=5)
frame2.pack(side='left',padx=5,pady=5)
frame3.pack(side='left',padx=5,pady=5)

tk.Label(frame1,text="输入密钥：").pack()
key=tk.StringVar(frame1)
tk.Entry(frame1,width=26,textvariable=key).pack()

convertrules=tk.Text(frame2,width=10,height=13)
convertrules.configure(state='disabled')
convertrules.pack()

plain=tk.StringVar()
tk.Label(frame3,text="明文：").pack()
tk.Entry(frame3,width=30,textvariable=plain).pack()
tk.Button(frame3,text="加密",anchor='e',command=encrypt).pack()
cipher=tk.StringVar()
tk.Label(frame3,text="密文：").pack()
tk.Entry(frame3,width=30,textvariable=cipher).pack()
tk.Button(frame3,text="解密",anchor='e',command=decrypt).pack()

tk.mainloop()