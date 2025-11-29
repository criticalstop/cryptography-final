import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
import time
import base64  # 导入base64模块

root=tk.Tk()
root.title("des加密")

'''函数部分'''
#对表示二进制的字符串补零操作
def addzeros(string,bits):
    while len(string)<bits:
        string='0'+string
    return string

#普通的循环左移
def rol(string,times):
    for i in range(times):
        string=string[1:]+string[0]
    return string

#密钥置换1，func(string(56))->string(28),string(28)
def key_permutation(data):
    pc1=[57,49,41,33,25,17,9,1,
    58,50,42,34,26,18,10,2,
    59,51,43,35,27,19,11,3,
    60,52,44,36,63,55,47,39,
    31,23,15,7,62,54,46,38,
    30,22,14,6,61,53,45,37,
    29,21,13,5,28,20,12,4]
    result="".join([data[i-1]for i in pc1])
    return result[0:28],result[28:]

#密钥置换2，func(string(28),string(28))->string(48)
def key_permutation_2(data1,data2):
    pc2=[14,17,11,24,1,5,
    3,28,15,6,21,10,
    23,19,12,4,26,8,
    16,7,27,20,13,2,
    41,52,31,37,47,55,
    30,40,51,45,33,48,
    44,49,39,56,34,53,
    46,42,50,36,29,32]
    data=data1+data2
    result="".join([data[i-1] for i in pc2])
    return result

#密钥生成，func(string(8))->list(16)[string(48),……] 
def keygen(keytext):
    rol_rules=[1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
    keybin=""
    keychain=[]#返回结果
    for char in keytext:
        keybin+=addzeros(bin(ord(char))[2:],8)#根据des规范只能默认奇偶校验位正确了,强制变成64位的
    key_l,key_r=key_permutation(keybin)
    for time in range(0,16):
        key_l=rol(key_l,rol_rules[time])
        key_r=rol(key_r,rol_rules[time])
        keychain.append(key_permutation_2(key_l,key_r))
    return keychain

#初始置换，func(string(64)) ->string(32),string(32)
def initial_permutation(data):
    ip_box=[58,50,42,34,26,18,10,2,
    60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6,
    64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,
    59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5,
    63,55,47,39,31,23,15,7]
    result="".join([data[i-1] for i in ip_box])
    return result[0:32],result[32:]

#e盒变换拓展,func(string(32))->string(48)
def text_extend(data):
    result=[]
    e_box=[32,1,2,3,4,5,
    4,5,6,7,8,9,
    8,9,10,11,12,13,
    12,13,14,15,16,17,
    16,17,18,19,20,21,
    20,21,22,23,24,25,
    24,25,26,27,28,29,
    28,29,30,31,32,1]
    result="".join([data[i-1] for i in e_box])
    return result

#字符串异或:
def str_xor(my_str1,my_str2):  #str，key
    res = ""
    for i in range(0,len(my_str1)):
        xor_res = int(my_str1[i],10)^int(my_str2[i],10)
        res += '1' if xor_res == 1 else '0'
    return res

#s盒加密操作，string(48)->string(32)
def s_permutation(data):
    result=""
    s_box=[[[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
    [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
    [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
    [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13]],

    [[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
    [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
    [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
    [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9]],

    [[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
    [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
    [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
    [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12]],

    [[ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
    [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
    [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
    [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14]],

    [[ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
    [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
    [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
    [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3]],

    [[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
    [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
    [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
    [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13]],

    [[ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
    [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
    [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
    [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12]],

    [[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
    [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
    [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
    [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11]]]
    for i in range(0,48,6):
        data_chunk=data[i:i+6]
        row=int('0b'+data_chunk[0]+data_chunk[-1],2)
        col=int('0b'+data_chunk[1:5],2)
        result+=addzeros(bin(s_box[i//6][row][col])[2:],4)
    return result

#p盒转换,func(string(32))->string(32)
def p_permutation(data):
    p_box=[
    16,7,20,21,
    29,12,28,17,
    1,15,23,26,
    5,18,31,10,
    2,8,24,14,
    32,27,3,9,
    19,13,30,6,
    22,11,4,25]
    result="".join([data[i-1] for i in p_box])
    return result

#最终置换，func(string(32),string(32))->string(64)
def final_permutation(str1,str2):
    string=str1+str2
    ip_box=[40,8,48,16,56,24,64,32,
    39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30,
    37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,
    35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26,
    33,1,41,9,49,17,57,25]
    result="".join([string[i-1] for i in ip_box])
    return result

#文字过一次des的加密操作，返回bytes
def des_once_e(plaintext_bytes, keychain):
    if iv.get()!='':
        IV=iv.get()[:8].encode('utf-8')
        iv_bin=""
        for b in IV:
            iv_bin+=addzeros(bin(b)[2:],8)
        while len(iv_bin)<64:
            iv_bin+="0"
    else:
        IV=''
        
    result_bin = ""

    # 处理明文，确保长度为8的倍数
    remainder = len(plaintext_bytes) % 8
    if remainder != 0:
        plaintext_bytes += b'\0' * (8 - remainder)
    
    for i in range(0, len(plaintext_bytes), 8):
        chunk = plaintext_bytes[i:i+8]
        bin_chunk = ""
        for b in chunk:
            bin_chunk += addzeros(bin(b)[2:], 8)
        
        if IV != '':
            bin_chunk = str_xor(iv_bin, bin_chunk)
        
        left, right = initial_permutation(bin_chunk)
        for j in range(16):
            right_new = right
            right_new = text_extend(right_new)
            right_new = str_xor(right_new, keychain[j])
            right_new = s_permutation(right_new)
            right_new = p_permutation(right_new)
            right, left = str_xor(left, right_new), right
        
        bin_result = final_permutation(right, left)
        result_bin += bin_result
        
        if IV != '':
            iv_bin = bin_result
    
    # 将二进制字符串转换为bytes
    result_bytes = b''
    for i in range(0, len(result_bin), 8):
        byte = int(result_bin[i:i+8], 2).to_bytes(1, 'big')
        result_bytes += byte
    
    return result_bytes

#文字过一次des的解密操作，返回bytes
def des_once_d(ciphertext_bytes, keychain):
    if iv.get()!='':
        IV=iv.get()[:8].encode('utf-8')
        iv_bin=""
        for b in IV:
            iv_bin+=addzeros(bin(b)[2:],8)
        while len(iv_bin)<64:
            iv_bin+="0"
    else:
        IV=''
    
    result_bin = ""
    
    for i in range(0, len(ciphertext_bytes), 8):
        chunk = ciphertext_bytes[i:i+8]
        bin_chunk = ""
        for b in chunk:
            bin_chunk += addzeros(bin(b)[2:], 8)
        
        last_bin_chunk = bin_chunk if IV != '' else ''
        
        left, right = initial_permutation(bin_chunk)
        for j in range(16):
            right_new = right
            right_new = text_extend(right_new)
            right_new = str_xor(right_new, keychain[j])
            right_new = s_permutation(right_new)
            right_new = p_permutation(right_new)
            right, left = str_xor(left, right_new), right
        
        bin_result = final_permutation(right, left)
        
        if IV != '':
            bin_result = str_xor(bin_result, iv_bin)
            iv_bin = last_bin_chunk
        
        result_bin += bin_result
    
    # 将二进制字符串转换为bytes
    result_bytes = b''
    for i in range(0, len(result_bin), 8):
        byte = int(result_bin[i:i+8], 2).to_bytes(1, 'big')
        result_bytes += byte
    
    return result_bytes

#des加密文字
def encrypt_text():
    starttime=time.time()
    try:
        keychain=keygen(key.get()[:8])
    except:
        messagebox.showerror("错误","请先输入密钥！")
        return
    
    # 获取明文并转换为bytes
    plaintext = plain.get(1.0,'end')[:-1]
    plaintext_bytes = plaintext.encode('GB2312')
    
    # 加密得到bytes结果
    cipher_bytes = des_once_e(plaintext_bytes, keychain)
    
    # 进行Base64编码以便显示
    b64_cipher = base64.b64encode(cipher_bytes).decode('utf-8')
    
    endtime=time.time()
    cipher.delete(1.0, 'end')
    cipher.insert(1.0, b64_cipher)
    time_elapsed.set("加密时间："+str(endtime-starttime)[:6]+"秒")

#des解密文字
def decrypt_text():
    starttime=time.time()
    try:
        keychain=keygen(key.get()[:8])
    except:
        messagebox.showerror("错误","请先输入密钥！")
        return
    keychain.reverse()
    
    # 获取Base64编码的密文并解码
    b64_cipher = cipher.get(1.0,'end')[:-1]
    try:
        cipher_bytes = base64.b64decode(b64_cipher)
    except:
        messagebox.showerror("错误","密文格式不正确，请确保是Base64编码！")
        return
    
    # 解密得到bytes结果
    plain_bytes = des_once_d(cipher_bytes, keychain)
    
    endtime=time.time()
    try:
        # 去除填充的空字符并解码
        plaintext = plain_bytes.rstrip(b'\0').decode('GB2312')
        plain.delete(1.0, 'end')
        plain.insert(1.0, plaintext)
    except UnicodeDecodeError:
        messagebox.showerror("错误","解密失败，请确认密钥和加密模式是否正确！")
        return
    time_elapsed.set("解密时间："+str(endtime-starttime)[:6]+"秒")

#3des加密文字
def encrypt_text_3():
    starttime=time.time()
    try:
        key1 = key.get()[:8]
        key2 = key.get()[8:16]
        key3 = key.get()[16:24]
        keychain1=keygen(key1)
        keychain2=keygen(key2)
        keychain3=keygen(key3)
    except:
        messagebox.showerror("错误","请输入至少24位密钥！")
        return
    
    # 获取明文并转换为bytes
    plaintext = plain.get(1.0,'end')[:-1]
    plaintext_bytes = plaintext.encode('GB2312')
    
    # 3DES加密
    result1 = des_once_e(plaintext_bytes, keychain1)
    result2 = des_once_d(result1, keychain2)  # 3DES通常是加密-解密-加密
    result3 = des_once_e(result2, keychain3)
    
    # 进行Base64编码以便显示
    b64_cipher = base64.b64encode(result3).decode('utf-8')
    
    endtime=time.time()
    cipher.delete(1.0, 'end')
    cipher.insert(1.0, b64_cipher)
    time_elapsed.set("加密时间："+str(endtime-starttime)[:6]+"秒")

#3des解密文字
def decrypt_text_3():
    starttime=time.time()
    try:
        key1 = key.get()[:8]
        key2 = key.get()[8:16]
        key3 = key.get()[16:24]
        keychain1=keygen(key1)
        keychain2=keygen(key2)
        keychain3=keygen(key3)
    except:
        messagebox.showerror("错误","请输入至少24位密钥！")
        return
    
    # 解密密钥顺序相反，且每个密钥链需要反转
    keychain1.reverse()
    keychain2.reverse()
    keychain3.reverse()
    
    # 获取Base64编码的密文并解码
    b64_cipher = cipher.get(1.0,'end')[:-1]
    try:
        cipher_bytes = base64.b64decode(b64_cipher)
    except:
        messagebox.showerror("错误","密文格式不正确，请确保是Base64编码！")
        return
    
    # 3DES解密
    result1 = des_once_d(cipher_bytes, keychain3)
    result2 = des_once_e(result1, keychain2)  # 3DES解密是解密-加密-解密
    result3 = des_once_d(result2, keychain1)
    
    endtime=time.time()
    try:
        # 去除填充的空字符并解码
        plaintext = result3.rstrip(b'\0').decode('GB2312')
        plain.delete(1.0, 'end')
        plain.insert(1.0, plaintext)
    except UnicodeDecodeError:
        messagebox.showerror("错误","解密失败，请确认密钥和加密模式是否正确！")
        return
    time_elapsed.set("解密时间："+str(endtime-starttime)[:6]+"秒")

#des加密文件
def encrypt_file():
    if file.get()=='' or folder.get()=='':
        messagebox.showerror("错误","请先选择文件/文件夹路径！")
        return
    if not outfilename.get():
        messagebox.showerror("错误","请输入输出文件名！")
        return
    
    starttime=time.time()
    # 读取文件内容为bytes
    with open(file.get(),"rb") as fp:
        file_bytes = fp.read()
    
    try:
        keychain=keygen(key.get()[:8])
    except:
        messagebox.showerror("错误","请先输入密钥！")
        return
    
    # 加密
    encrypted_bytes = des_once_e(file_bytes, keychain)
    
    # 保存加密后的文件
    output_path = f"{folder.get()}/{outfilename.get()}"
    with open(output_path,"wb") as fp:
        fp.write(encrypted_bytes)
    
    endtime=time.time()
    time_elapsed.set("加密时间："+str(endtime-starttime)[:6]+"秒")
    messagebox.showinfo("成功",f"文件已加密并保存至：{output_path}")

#des解密文件
def decrypt_file():
    if file.get()=='' or folder.get()=='':
        messagebox.showerror("错误","请先选择文件/文件夹路径！")
        return
    if not outfilename.get():
        messagebox.showerror("错误","请输入输出文件名！")
        return
    
    starttime=time.time()
    # 读取加密文件内容为bytes
    with open(file.get(),"rb") as fp:
        encrypted_bytes = fp.read()
    
    try:
        keychain=keygen(key.get()[:8])
    except:
        messagebox.showerror("错误","请先输入密钥！")
        return
    keychain.reverse()
    
    # 解密
    decrypted_bytes = des_once_d(encrypted_bytes, keychain)
    
    # 保存解密后的文件
    output_path = f"{folder.get()}/{outfilename.get()}"
    with open(output_path,"wb") as fp:
        fp.write(decrypted_bytes)
    
    endtime=time.time()
    time_elapsed.set("解密时间："+str(endtime-starttime)[:6]+"秒")
    messagebox.showinfo("成功",f"文件已解密并保存至：{output_path}")

#3des加密文件
def encrypt_file_3():
    if file.get()=='' or folder.get()=='':
        messagebox.showerror("错误","请先选择文件/文件夹路径！")
        return
    if not outfilename.get():
        messagebox.showerror("错误","请输入输出文件名！")
        return
    
    starttime=time.time()
    # 读取文件内容为bytes
    with open(file.get(),"rb") as fp:
        file_bytes = fp.read()
    
    try:
        key1 = key.get()[:8]
        key2 = key.get()[8:16]
        key3 = key.get()[16:24]
        keychain1=keygen(key1)
        keychain2=keygen(key2)
        keychain3=keygen(key3)
    except:
        messagebox.showerror("错误","请输入至少24位密钥！")
        return
    
    # 3DES加密
    result1 = des_once_e(file_bytes, keychain1)
    result2 = des_once_d(result1, keychain2)
    result3 = des_once_e(result2, keychain3)
    
    # 保存加密后的文件
    output_path = f"{folder.get()}/{outfilename.get()}"
    with open(output_path,"wb") as fp:
        fp.write(result3)
    
    endtime=time.time()
    time_elapsed.set("加密时间："+str(endtime-starttime)[:6]+"秒")
    messagebox.showinfo("成功",f"文件已加密并保存至：{output_path}")

#3des解密文件
def decrypt_file_3():
    if file.get()=='' or folder.get()=='':
        messagebox.showerror("错误","请先选择文件/文件夹路径！")
        return
    if not outfilename.get():
        messagebox.showerror("错误","请输入输出文件名！")
        return
    
    starttime=time.time()
    # 读取加密文件内容为bytes
    with open(file.get(),"rb") as fp:
        encrypted_bytes = fp.read()
    
    try:
        key1 = key.get()[:8]
        key2 = key.get()[8:16]
        key3 = key.get()[16:24]
        keychain1=keygen(key1)
        keychain2=keygen(key2)
        keychain3=keygen(key3)
    except:
        messagebox.showerror("错误","请输入至少24位密钥！")
        return
    
    # 解密密钥处理
    keychain1.reverse()
    keychain2.reverse()
    keychain3.reverse()
    
    # 3DES解密
    result1 = des_once_d(encrypted_bytes, keychain3)
    result2 = des_once_e(result1, keychain2)
    result3 = des_once_d(result2, keychain1)
    
    # 保存解密后的文件
    output_path = f"{folder.get()}/{outfilename.get()}"
    with open(output_path,"wb") as fp:
        fp.write(result3)
    
    endtime=time.time()
    time_elapsed.set("解密时间："+str(endtime-starttime)[:6]+"秒")
#---------------------------------
'''gui部分'''
#---------------------------------
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
frame4=tk.Frame(root,padx=5,pady=5)

frame1.pack(side='left')
frame2.pack(side='left')
frame3.pack(side='left')
frame4.pack(side='left')

tk.Label(frame1,text="密钥：\n(3DES需要24位)").pack()
key=tk.StringVar()
tk.Entry(frame1,textvariable=key,width=30).pack()
tk.Label(frame1,text="初始向量:\n（留空即使用ecb模式，填写后使用cbc模式）").pack()
iv=tk.StringVar()
tk.Entry(frame1,textvariable=iv).pack()
time_elapsed=tk.StringVar()
time_elapsed.set("加/解密时间：未开始")
tk.Label(frame1,textvariable=time_elapsed).pack()

tk.Label(frame2,text="明文：").pack()
plain=tk.Text(frame2,width=30,height=10)
plain.pack()

tk.Label(frame2,text="密文（Base64）：").pack()
cipher=tk.Text(frame2,width=30,height=10)
cipher.pack()

tk.Label(frame3,text="待处理文件：").pack()
file=tk.StringVar()
tk.Entry(frame3,textvariable=file,width=30).pack()
tk.Button(frame3,text="选择文件",command=selectfile).pack()
tk.Label(frame3,text="输出路径：").pack()
folder=tk.StringVar()
tk.Entry(frame3,textvariable=folder,width=30).pack()
tk.Button(frame3,text="选择文件夹",command=selectfolder).pack()
tk.Label(frame3,text="输出文件名：").pack()
outfilename=tk.StringVar()
tk.Entry(frame3,textvariable=outfilename,width=30).pack()

tk.Button(frame4,text="des加密文字",anchor='e',pady=5,command=encrypt_text).pack()
tk.Button(frame4,text="3des加密文字",anchor='e',pady=5,command=encrypt_text_3).pack()
tk.Button(frame4,text="des解密文字",anchor='e',pady=5,command=decrypt_text).pack()
tk.Button(frame4,text="3des解密文字",anchor='e',pady=5,command=decrypt_text_3).pack()
tk.Button(frame4,text="des加密文件",anchor='e',pady=5,command=encrypt_file).pack()
tk.Button(frame4,text="3des加密文件",anchor='e',pady=5,command=encrypt_file_3).pack()
tk.Button(frame4,text="des解密文件",anchor='e',pady=5,command=decrypt_file).pack()
tk.Button(frame4,text="3des解密文件",anchor='e',pady=5,command=decrypt_file_3).pack()

root.mainloop()