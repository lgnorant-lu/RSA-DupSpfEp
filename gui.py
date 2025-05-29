"""
---------------------------------------------------------------
File name:                   gui.py
Author:                      Ignorant-lu
Date created:                2025/05/29
Description:                 提供 RSA 加解密工具的图形用户界面 (GUI).
----------------------------------------------------------------

Changed history:
                             2025/05/29: 初始创建, 搭建 Tkinter 框架;
                             2025/05/29: 添加日志区域和输出重定向;
                             2025/05/29: 实现密钥生成 Tab 页;
----
"""

import tkinter as tk
from tkinter import ttk  # Themed widgets
from tkinter import filedialog
from tkinter import messagebox
from tkinter import scrolledtext
import sys
import threading # 用于在后台运行耗时操作, 避免 GUI 卡死
import base64

import rsa_core # 导入我们的核心库

class TextRedirector(object):
    """一个将 print 输出重定向到 Tkinter Text 控件的类."""
    def __init__(self, widget):
        self.widget = widget

    def write(self, str_):
        """将字符串写入 Text 控件."""
        # 必须先设置为 normal 才能写入, 写完再 disabled 防止用户编辑
        self.widget.configure(state='normal')
        self.widget.insert('end', str_)
        self.widget.see('end')  # 自动滚动到末尾
        self.widget.configure(state='disabled')
        self.widget.update_idletasks() # 确保界面更新

    def flush(self):
        """标准输出/错误需要的 flush 方法, 这里我们什么都不做."""
        pass

class RsaApp(tk.Tk):
    """RSA 加解密工具的主 GUI 应用类."""

    def __init__(self):
        super().__init__()

        self.title("RSA 加解密工具 (by Ignorant-lu)")
        self.geometry("700x600") # 设置初始窗口大小

        # --- 存储密钥信息 ---
        self.public_key = None
        self.private_key = None
        self.p = None
        self.q = None

        # --- 创建主框架 ---
        main_frame = ttk.Frame(self, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- 创建 Tab 控件 ---
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        # --- 创建各个 Tab 页 (先创建空的 Frame) ---
        self.tab_keygen = ttk.Frame(self.notebook, padding="10")
        self.tab_encrypt = ttk.Frame(self.notebook, padding="10")
        self.tab_decrypt = ttk.Frame(self.notebook, padding="10")

        self.notebook.add(self.tab_keygen, text=' 密钥生成 ')
        self.notebook.add(self.tab_encrypt, text=' 加密 ')
        self.notebook.add(self.tab_decrypt, text=' 解密 ')

        # --- 创建日志区域 ---
        log_frame = ttk.LabelFrame(main_frame, text="日志输出", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(log_frame, height=10, state='disabled', wrap=tk.WORD)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        log_scrollbar = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.log_text.yview)
        log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text['yscrollcommand'] = log_scrollbar.set

        # --- 重定向上/ stderr ---
        sys.stdout = TextRedirector(self.log_text)
        sys.stderr = TextRedirector(self.log_text)

        # --- 填充各个 Tab 页的内容 ---
        self.create_keygen_tab()
        self.create_encrypt_tab() 
        self.create_decrypt_tab()

        print("欢迎使用 RSA 加解密工具.")

    def create_keygen_tab(self):
        """创建密钥生成 Tab 页的控件."""
        frame = self.tab_keygen

        # --- 参数设置 ---
        param_frame = ttk.LabelFrame(frame, text="参数设置", padding="10")
        param_frame.pack(fill=tk.X, pady=5)

        ttk.Label(param_frame, text="密钥位数:").pack(side=tk.LEFT, padx=5)
        self.bits_var = tk.StringVar(value="512") # 默认 512, 便于测试
        bits_entry = ttk.Entry(param_frame, textvariable=self.bits_var, width=10)
        bits_entry.pack(side=tk.LEFT, padx=5)

        generate_button = ttk.Button(param_frame, text="生成密钥对", command=self.generate_keys_thread)
        generate_button.pack(side=tk.LEFT, padx=20)

        # --- 密钥显示 ---
        key_frame = ttk.LabelFrame(frame, text="密钥信息", padding="10")
        key_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        key_labels = ["N (模数):", "e (公钥指数):", "d (私钥指数):"]
        self.key_vars = {}

        for i, label_text in enumerate(key_labels):
            ttk.Label(key_frame, text=label_text).grid(row=i, column=0, sticky=tk.W, pady=2, padx=5)
            var = tk.StringVar(value="--- 未生成 ---")
            self.key_vars[label_text] = var
            entry = ttk.Entry(key_frame, textvariable=var, state='readonly', width=70)
            entry.grid(row=i, column=1, sticky=tk.EW, pady=2, padx=5)
        
        key_frame.columnconfigure(1, weight=1) # 让输入框可以扩展

        # --- 保存密钥 ---
        save_frame = ttk.Frame(frame, padding="10")
        save_frame.pack(fill=tk.X, pady=5)
        
        save_pub_button = ttk.Button(save_frame, text="保存公钥", command=self.save_public_key)
        save_pub_button.pack(side=tk.LEFT, padx=10)
        
        save_priv_button = ttk.Button(save_frame, text="保存私钥", command=self.save_private_key)
        save_priv_button.pack(side=tk.LEFT, padx=10)

    def generate_keys_thread(self):
        """使用线程来生成密钥, 避免 GUI 卡死."""
        try:
            bits = int(self.bits_var.get())
            if bits < 128: # 简单检查
                messagebox.showerror("错误", "密钥位数太小, 至少需要 128 位.")
                return
            # 在新线程中运行耗时的 generate_key_pair
            thread = threading.Thread(target=self.generate_keys_action, args=(bits,))
            thread.start()
        except ValueError:
            messagebox.showerror("错误", "请输入有效的密钥位数 (整数).")

    def generate_keys_action(self, bits):
        """实际执行密钥生成并更新 GUI 的函数."""
        try:
            self.public_key, self.private_key, self.p, self.q = rsa_core.generate_key_pair(bits)
            e, N = self.public_key
            d, _ = self.private_key
            
            # 更新 GUI (必须在主线程中操作, 但 print 可以直接用)
            # 对于简单的更新, 直接在线程里 print 也可以通过重定向显示.
            # 但要更新 StringVar, 严格来说需要使用线程安全的方法, 
            # 不过对于这种一次性更新, 直接设置通常也能工作, 但不是最佳实践.
            # 这里我们先直接设置:
            self.key_vars["N (模数):"].set(str(N))
            self.key_vars["e (公钥指数):"].set(str(e))
            self.key_vars["d (私钥指数):"].set(str(d))
            
            messagebox.showinfo("成功", "密钥对生成成功!")

        except Exception as e:
            messagebox.showerror("生成失败", f"生成密钥时发生错误:\n{e}")

    def save_public_key(self):
        """保存公钥到文件."""
        if not self.public_key:
            messagebox.showwarning("警告", "请先生成密钥.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="保存公钥",
            defaultextension=".pem",
            filetypes=[("PEM 文件", "*.pem"), ("所有文件", "*.*")]
        )
        if filename:
            try:
                rsa_core.save_pem_public_key(self.public_key, filename)
                messagebox.showinfo("成功", f"公钥已保存到 {filename}")
            except Exception as e:
                messagebox.showerror("保存失败", f"保存公钥时发生错误:\n{e}")

    def save_private_key(self):
        """保存私钥到文件."""
        if not self.private_key or not self.p or not self.q:
            messagebox.showwarning("警告", "请先生成密钥.")
            return
            
        filename = filedialog.asksaveasfilename(
            title="保存私钥",
            defaultextension=".pem",
            filetypes=[("PEM 文件", "*.pem"), ("所有文件", "*.*")]
        )
        if filename:
            try:
                rsa_core.save_pem_private_key(self.public_key, self.private_key, self.p, self.q, filename)
                messagebox.showinfo("成功", f"私钥已保存到 {filename}")
            except Exception as e:
                messagebox.showerror("保存失败", f"保存私钥时发生错误:\n{e}")

    # -------

    def create_encrypt_tab(self):
        """创建加密 Tab 页的控件."""
        frame = self.tab_encrypt
        
        # --- 公钥区 ---
        key_frame = ttk.LabelFrame(frame, text="公钥", padding="10")
        key_frame.pack(fill=tk.X, pady=5)
        
        self.enc_pub_key_label = tk.StringVar(value="N: ---\ne: ---")
        ttk.Label(key_frame, textvariable=self.enc_pub_key_label, justify=tk.LEFT).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_frame, text="加载公钥文件", command=self.load_public_key_encrypt).pack(side=tk.RIGHT, padx=5)

        # --- 输入区 ---
        input_frame = ttk.LabelFrame(frame, text="输入明文", padding="10")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.enc_input_mode = tk.StringVar(value="text") # 默认文本输入

        def toggle_input_mode():
            if self.enc_input_mode.get() == "text":
                self.enc_text_input.pack(fill=tk.BOTH, expand=True)
                file_input_row.pack_forget() # 隐藏文件输入行
            else:
                self.enc_text_input.pack_forget() # 隐藏文本输入区
                file_input_row.pack(fill=tk.X, pady=5)

        ttk.Radiobutton(input_frame, text="文本输入", variable=self.enc_input_mode, value="text", command=toggle_input_mode).pack(anchor=tk.W)
        self.enc_text_input = scrolledtext.ScrolledText(input_frame, height=5, wrap=tk.WORD)
        
        ttk.Radiobutton(input_frame, text="文件输入", variable=self.enc_input_mode, value="file", command=toggle_input_mode).pack(anchor=tk.W)
        file_input_row = ttk.Frame(input_frame)
        self.enc_input_file = tk.StringVar()
        ttk.Entry(file_input_row, textvariable=self.enc_input_file, state='readonly', width=50).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        ttk.Button(file_input_row, text="浏览...", command=self.browse_input_file_encrypt).pack(side=tk.LEFT)

        toggle_input_mode() # 初始化显示

        # --- 输出区 ---
        output_frame = ttk.LabelFrame(frame, text="输出密文 (Base64)", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.enc_text_output = scrolledtext.ScrolledText(output_frame, height=5, wrap=tk.WORD, state='disabled')
        self.enc_text_output.pack(fill=tk.BOTH, expand=True)

        # --- 操作区 ---
        action_frame = ttk.Frame(frame, padding="10")
        action_frame.pack(fill=tk.X)
        
        self.enc_output_file = tk.StringVar() # 用于文件模式输出
        ttk.Button(action_frame, text="执行加密", command=self.encrypt_action_thread).pack(expand=True)

    def load_public_key_encrypt(self):
        """加载用于加密的公钥."""
        filename = filedialog.askopenfilename(
            title="选择公钥文件",
            filetypes=[("PEM 文件", "*.pem"), ("所有文件", "*.*")]
        )
        if filename:
            try:
                self.public_key = rsa_core.load_pem_public_key(filename)
                e, N = self.public_key
                self.enc_pub_key_label.set(f"N: {str(N)[:30]}...\ne: {e}")
                print(f"公钥 {filename} 加载成功.")
            except Exception as e:
                messagebox.showerror("加载失败", f"加载公钥时发生错误:\n{e}")
                self.public_key = None
                self.enc_pub_key_label.set("N: ---\ne: ---")

    def browse_input_file_encrypt(self):
        """浏览选择要加密的输入文件."""
        filename = filedialog.askopenfilename(title="选择明文文件")
        if filename:
            self.enc_input_file.set(filename)

    def encrypt_action_thread(self):
        """使用线程执行加密操作."""
        if not self.public_key:
            messagebox.showwarning("警告", "请先加载公钥.")
            return

        thread = threading.Thread(target=self.encrypt_action)
        thread.start()

    def encrypt_action(self):
        """实际执行加密操作."""
        mode = self.enc_input_mode.get()
        
        try:
            if mode == "text":
                message = self.enc_text_input.get("1.0", tk.END).strip()
                if not message:
                    messagebox.showwarning("警告", "请输入要加密的文本.")
                    return
                print("正在加密文本...")
                message_bytes = message.encode('utf-8')
                encrypted_bytes = rsa_core.encrypt_large(message_bytes, self.public_key)
                encrypted_base64 = base64.b64encode(encrypted_bytes).decode('ascii')
                
                # 更新输出文本框
                self.enc_text_output.configure(state='normal')
                self.enc_text_output.delete('1.0', tk.END)
                self.enc_text_output.insert('1.0', encrypted_base64)
                self.enc_text_output.configure(state='disabled')
                print("文本加密成功, 密文已显示 (Base64).")

            elif mode == "file":
                input_file = self.enc_input_file.get()
                if not input_file:
                    messagebox.showwarning("警告", "请选择要加密的文件.")
                    return
                
                output_file = filedialog.asksaveasfilename(
                    title="保存加密文件",
                    defaultextension=".enc",
                    filetypes=[("加密文件", "*.enc"), ("所有文件", "*.*")]
                )
                if not output_file:
                    return # 用户取消保存

                rsa_core.encrypt_file(input_file, output_file, self.public_key)
                messagebox.showinfo("成功", f"文件已成功加密到\n{output_file}")

        except Exception as e:
            messagebox.showerror("加密失败", f"加密过程中发生错误:\n{e}")

    # -------
    def create_decrypt_tab(self):
        """创建解密 Tab 页的控件."""
        frame = self.tab_decrypt

        # --- 私钥区 ---
        key_frame = ttk.LabelFrame(frame, text="私钥", padding="10")
        key_frame.pack(fill=tk.X, pady=5)

        self.dec_priv_key_label = tk.StringVar(value="N: ---") # 只显示 N, 避免 d 泄露
        ttk.Label(key_frame, textvariable=self.dec_priv_key_label, justify=tk.LEFT).pack(side=tk.LEFT, padx=5)
        ttk.Button(key_frame, text="加载私钥文件", command=self.load_private_key_decrypt).pack(side=tk.RIGHT, padx=5)

        # --- 输入区 ---
        input_frame = ttk.LabelFrame(frame, text="输入密文", padding="10")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.dec_input_mode = tk.StringVar(value="text") # 默认文本输入

        def toggle_input_mode():
            if self.dec_input_mode.get() == "text":
                self.dec_text_input.pack(fill=tk.BOTH, expand=True)
                file_input_row.pack_forget()
                input_frame.config(text="输入密文 (Base64)") # 提示输入 Base64
            else:
                self.dec_text_input.pack_forget()
                file_input_row.pack(fill=tk.X, pady=5)
                input_frame.config(text="输入密文")

        ttk.Radiobutton(input_frame, text="文本输入 (Base64)", variable=self.dec_input_mode, value="text", command=toggle_input_mode).pack(anchor=tk.W)
        self.dec_text_input = scrolledtext.ScrolledText(input_frame, height=5, wrap=tk.WORD)

        ttk.Radiobutton(input_frame, text="文件输入", variable=self.dec_input_mode, value="file", command=toggle_input_mode).pack(anchor=tk.W)
        file_input_row = ttk.Frame(input_frame)
        self.dec_input_file = tk.StringVar()
        ttk.Entry(file_input_row, textvariable=self.dec_input_file, state='readonly', width=50).pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        ttk.Button(file_input_row, text="浏览...", command=self.browse_input_file_decrypt).pack(side=tk.LEFT)

        toggle_input_mode() # 初始化显示

        # --- 输出区 ---
        output_frame = ttk.LabelFrame(frame, text="输出明文", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.dec_text_output = scrolledtext.ScrolledText(output_frame, height=5, wrap=tk.WORD, state='disabled')
        self.dec_text_output.pack(fill=tk.BOTH, expand=True)

        # --- 操作区 ---
        action_frame = ttk.Frame(frame, padding="10")
        action_frame.pack(fill=tk.X)

        ttk.Button(action_frame, text="执行解密", command=self.decrypt_action_thread).pack(expand=True)

    def load_private_key_decrypt(self):
        """加载用于解密的私钥."""
        filename = filedialog.askopenfilename(
            title="选择私钥文件",
            filetypes=[("PEM 文件", "*.pem"), ("所有文件", "*.*")]
        )
        if filename:
            try:
                # 加载会返回 ((e, N), (d, N), p, q)
                pub, priv, p, q = rsa_core.load_pem_private_key(filename)
                self.public_key = pub  # 也存起来, 万一要用
                self.private_key = priv
                self.p = p
                self.q = q
                
                _, N = self.private_key
                self.dec_priv_key_label.set(f"N: {str(N)[:50]}...") # 只显示 N
                print(f"私钥 {filename} 加载成功.")
            except Exception as e:
                messagebox.showerror("加载失败", f"加载私钥时发生错误:\n{e}")
                self.private_key = None
                self.dec_priv_key_label.set("N: ---")

    def browse_input_file_decrypt(self):
        """浏览选择要解密的输入文件."""
        filename = filedialog.askopenfilename(title="选择密文文件")
        if filename:
            self.dec_input_file.set(filename)

    def decrypt_action_thread(self):
        """使用线程执行解密操作."""
        if not self.private_key:
            messagebox.showwarning("警告", "请先加载私钥.")
            return

        thread = threading.Thread(target=self.decrypt_action)
        thread.start()

    def decrypt_action(self):
        """实际执行解密操作."""
        mode = self.dec_input_mode.get()

        try:
            if mode == "text":
                ciphertext_base64 = self.dec_text_input.get("1.0", tk.END).strip()
                if not ciphertext_base64:
                    messagebox.showwarning("警告", "请输入要解密的 Base64 文本.")
                    return
                print("正在解密文本 (Base64)...")
                
                try:
                    ciphertext_bytes = base64.b64decode(ciphertext_base64.encode('ascii'))
                except Exception as e:
                    messagebox.showerror("解码失败", f"输入的 Base64 文本无效:\n{e}")
                    return

                decrypted_bytes = rsa_core.decrypt_large(ciphertext_bytes, self.private_key)
                
                try:
                    decrypted_text = decrypted_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    decrypted_text = f"*** 解码失败: 无法用 UTF-8 解析, 原始字节: {decrypted_bytes!r} ***"

                # 更新输出文本框
                self.dec_text_output.configure(state='normal')
                self.dec_text_output.delete('1.0', tk.END)
                self.dec_text_output.insert('1.0', decrypted_text)
                self.dec_text_output.configure(state='disabled')
                print("文本解密成功, 明文已显示.")

            elif mode == "file":
                input_file = self.dec_input_file.get()
                if not input_file:
                    messagebox.showwarning("警告", "请选择要解密的文件.")
                    return

                output_file = filedialog.asksaveasfilename(
                    title="保存解密文件",
                    defaultextension=".txt",
                    filetypes=[("文本文档", "*.txt"), ("所有文件", "*.*")]
                )
                if not output_file:
                    return # 用户取消保存

                rsa_core.decrypt_file(input_file, output_file, self.private_key)
                messagebox.showinfo("成功", f"文件已成功解密到\n{output_file}")

        except Exception as e:
            messagebox.showerror("解密失败", f"解密过程中发生错误:\n{e}")


# ---------------------------------------------------------------
# 运行 GUI
# ---------------------------------------------------------------

if __name__ == "__main__":
    app = RsaApp()
    app.mainloop()
