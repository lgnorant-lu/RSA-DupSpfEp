"""
---------------------------------------------------------------
File name:                   cli.py
Author:                      Ignorant-lu
Date created:                2025/05/29
Description:                 提供 RSA 加解密工具的命令行界面.
                             允许用户生成密钥、加密文件和解密文件.
----------------------------------------------------------------

Changed history:
                             2025/05/29: 初始创建, 添加 argparse 框架;
                             2025/05/29: 实现 generate, encrypt, decrypt 子命令;
----
"""

import argparse
import sys
import rsa_core # <--- 导入我们自己的核心库

# ---------------------------------------------------------------
# 命令行处理函数
# ---------------------------------------------------------------

def handle_generate(args):
    """处理 'generate' 命令."""
    try:
        print(f"正在生成 {args.bits} 位的密钥对...")
        public_key, private_key, p, q = rsa_core.generate_key_pair(args.bits)
        
        pub_filename = args.pubkey if args.pubkey else "public.pem"
        priv_filename = args.privkey if args.privkey else "private.pem"

        rsa_core.save_pem_public_key(public_key, pub_filename)
        rsa_core.save_pem_private_key(public_key, private_key, p, q, priv_filename)
        
        print(f"\n密钥对已成功生成并保存到 {pub_filename} 和 {priv_filename}.")

    except Exception as e:
        print(f"❌ 生成密钥时发生错误: {e}", file=sys.stderr)
        sys.exit(1)

def handle_encrypt(args):
    """处理 'encrypt' 命令."""
    try:
        print(f"正在从 {args.key} 加载公钥...")
        public_key = rsa_core.load_pem_public_key(args.key)
        
        rsa_core.encrypt_file(args.input, args.output, public_key)
        
    except FileNotFoundError as e:
        print(f"❌ 文件错误: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ 加密时发生错误: {e}", file=sys.stderr)
        sys.exit(1)

def handle_decrypt(args):
    """处理 'decrypt' 命令."""
    try:
        print(f"正在从 {args.key} 加载私钥...")
        # 加载私钥会返回 ((e, N), (d, N), p, q), 我们只需要私钥部分
        _, private_key, _, _ = rsa_core.load_pem_private_key(args.key)

        rsa_core.decrypt_file(args.input, args.output, private_key)

    except FileNotFoundError as e:
        print(f"❌ 文件错误: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"❌ 解密时发生错误: {e}", file=sys.stderr)
        sys.exit(1)

# ---------------------------------------------------------------
# 主程序入口
# ---------------------------------------------------------------

def main():
    """设置参数解析器并分派命令."""
    parser = argparse.ArgumentParser(
        description="RSA 加解密命令行工具.",
        formatter_class=argparse.RawTextHelpFormatter # 保持帮助信息格式
    )
    # 添加子命令解析器
    subparsers = parser.add_subparsers(dest='command', required=True, help="可用的子命令")

    # --- 'generate' 子命令 ---
    parser_gen = subparsers.add_parser(
        'generate', 
        help="生成新的 RSA 密钥对并保存为 PEM 格式."
    )
    parser_gen.add_argument(
        '--bits', 
        '-b', 
        type=int, 
        default=2048, 
        help="密钥位数 (例如: 512, 1024, 2048). 默认为 2048."
    )
    parser_gen.add_argument(
        '--pubkey', 
        '-p', 
        type=str, 
        default="public.pem", 
        help="保存公钥的文件名. 默认为 public.pem."
    )
    parser_gen.add_argument(
        '--privkey', 
        '-k', 
        type=str, 
        default="private.pem", 
        help="保存私钥的文件名. 默认为 private.pem."
    )
    parser_gen.set_defaults(func=handle_generate) # 关联处理函数

    # --- 'encrypt' 子命令 ---
    parser_enc = subparsers.add_parser(
        'encrypt', 
        help="使用公钥加密文件."
    )
    parser_enc.add_argument(
        '--key', 
        '-k', 
        type=str, 
        required=True, 
        help="用于加密的公钥 PEM 文件."
    )
    parser_enc.add_argument(
        '--input', 
        '-i', 
        type=str, 
        required=True, 
        help="要加密的明文文件名."
    )
    parser_enc.add_argument(
        '--output', 
        '-o', 
        type=str, 
        required=True, 
        help="保存加密后密文的文件名."
    )
    parser_enc.set_defaults(func=handle_encrypt) # 关联处理函数

    # --- 'decrypt' 子命令 ---
    parser_dec = subparsers.add_parser(
        'decrypt', 
        help="使用私钥解密文件."
    )
    parser_dec.add_argument(
        '--key', 
        '-k', 
        type=str, 
        required=True, 
        help="用于解密的私钥 PEM 文件."
    )
    parser_dec.add_argument(
        '--input', 
        '-i', 
        type=str, 
        required=True, 
        help="要解密的密文文件名."
    )
    parser_dec.add_argument(
        '--output', 
        '-o', 
        type=str, 
        required=True, 
        help="保存解密后明文的文件名."
    )
    parser_dec.set_defaults(func=handle_decrypt) # 关联处理函数

    # 解析参数
    args = parser.parse_args()

    # 调用选定子命令对应的处理函数
    args.func(args)

if __name__ == "__main__":
    main()