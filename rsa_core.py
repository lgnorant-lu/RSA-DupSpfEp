"""
---------------------------------------------------------------
File name:                         rsa_core.py
Author:                           Ignorant-lu
Date created:                       2025/05/28
Description:                        实现 RSA 算法的核心逻辑, 包括密钥生成、
                              加密、解密以及大素数生成等功能。
----------------------------------------------------------------

Changed history:
                             2025/05/28: 初始创建, 准备实现核心算法;
                             2025/05/28: 添加扩展欧几里得算法和模逆元函数;
                             2025/05/28: 添加 Miller-Rabin 素性检验函数;
                             2025/05/28: 添加大素数生成函数;
                             2025/05/28: 添加密钥对生成函数;
----
"""

import random
import sys
import os
import base64
import re
import binascii


# ---------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------

def _get_byte_length(n):
    """计算整数 n 的字节长度.

    Args:
        n (int): 一个整数 (通常是模数 N).

    Returns:
        int: 表示 n 所需的最小字节数.
    """
    # *** 新增: 特别处理 n = 0 的情况 ***
    if n == 0:
        return 1

    # 原有逻辑保持不变
    return (n.bit_length() + 7) // 8

def _int_to_bytes(n, length=None):
    """将整数转换为指定长度的字节串 (大端序).

    Args:
        n (int): 要转换的整数。
        length (int, optional): 期望的字节长度。如果为 None, 则使用最小长度。

    Returns:
        bytes: 转换后的字节串。
    """
    if length is None:
        length = _get_byte_length(n)
    return n.to_bytes(length, 'big')

def _bytes_to_int(b):
    """将字节串转换回整数 (大端序).

    Args:
        b (bytes): 要转换的字节串。

    Returns:
        int: 转换后的整数。
    """
    return int.from_bytes(b, 'big')

# ---------------------------------------------------------------
# 模块一: 基础数学工具
# ---------------------------------------------------------------

def egcd(a, b):
    """计算 a 和 b 的最大公约数, 并返回 (gcd, x, y) 使得 ax + by = gcd.

    Args:
        a: 第一个整数。
        b: 第二个整数。

    Returns:
        一个元组 (gcd, x, y), 其中 gcd 是 a 和 b 的最大公约数,
        且满足 a * x + b * y = gcd。
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    """计算 a 在模 m 下的乘法逆元.

    Args:
        a: 需要计算逆元的数。
        m: 模数。

    Returns:
        如果逆元存在, 返回 a 的模 m 逆元; 否则抛出异常。
    """
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('模逆元不存在 (Modular inverse does not exist)')
    else:
        return x % m

def is_prime(n, k=40):
    """使用 Miller-Rabin 算法检验 n 是否很可能是素数.

    Args:
        n: 待检验的整数。
        k: 检验次数 (默认为 40, 提供足够高的置信度)。

    Returns:
        如果 n 很可能是素数, 返回 True; 否则返回 False。
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    t = n - 1
    s = 0
    while t % 2 == 0:
        t //= 2
        s += 1

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, t, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == 1:
                return False
            if x == n - 1:
                break
        else:
            return False

    return True

def generate_large_prime(bits=1024):
    """生成一个指定位数的大素数.

    Args:
        bits: 素数的二进制位数 (例如 1024 或 2048)。

    Returns:
        一个指定位数的大素数。
    """
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits - 1))
        p |= 1

        if is_prime(p):
            return p

# ---------------------------------------------------------------
# 模块二: 密钥生成
# ---------------------------------------------------------------

def generate_key_pair(bits=2048):
    """生成 RSA 公钥和私钥对.

    Args:
        bits (int): 密钥的期望位数 (N 的位数)。 p 和 q 的位数将是 bits 的一半。
                    默认为 2048 位。

    Returns:
        tuple: ((e, N), (d, N), p, q), 公钥和私钥对, 与p, q值。
    """
    print(f"开始生成 {bits} 位的密钥对...")

    p_bits = bits // 2
    q_bits = bits - p_bits
    e = 65537

    while True:
        print("    正在生成大素数 p...")
        p = generate_large_prime(p_bits)
        print(f"    p 已生成 (部分显示): {str(p)[:20]}...")
        print("    正在生成大素数 q...")
        q = generate_large_prime(q_bits)
        print(f"    q 已生成 (部分显示): {str(q)[:20]}...")

        if p == q:
            print("    p 和 q 相等, 重新生成...")
            continue

        N = p * q
        print(f"    N 已计算 (部分显示): {str(N)[:20]}...")

        if N.bit_length() < bits:
            print(f"    N 的位数 ({N.bit_length()}) 小于期望值 ({bits}), 重新生成...")
            continue

        phi_n = (p - 1) * (q - 1)
        print(f"    phi(N) 已计算 (部分显示): {str(phi_n)[:20]}...")

        g, _, _ = egcd(e, phi_n)
        if g == 1:
            print(f"    gcd(e, phi_N) = 1, 条件满足。")
            print("    正在计算私钥指数 d...")
            d = modinv(e, phi_n)
            print(f"    d 已计算 (部分显示): {str(d)[:20]}...")
            print("密钥对生成成功！")
            return ((e, N), (d, N), p, q)
        else:
            print(f"    gcd(e, phi_N) = {g} (不为 1), 重新生成 p 和 q...")

# ---------------------------------------------------------------
# 模块三: PKCS#1 v1.5 填充与去填充
# ---------------------------------------------------------------

def pad_pkcs1_v1_5(message_bytes, n_modulus):
    """应用 PKCS#1 v1.5 (Type 2) 填充方案.

    Args:
        message_bytes (bytes): 要填充的原始消息字节串。
        n_modulus (int): RSA 模数 N。

    Returns:
        bytes: 经过填充的消息字节串, 长度等于 N 的字节长度 k。

    Raises:
        ValueError: 如果消息长度超过 k - 11。
    """
    k = _get_byte_length(n_modulus)
    m_len = len(message_bytes)

    # 检查消息长度是否符合要求
    if m_len > k - 11:
        raise ValueError(f"消息太长 ({m_len} 字节), 无法进行 PKCS#1 v1.5 填充 (最大 {k-11} 字节)")

    # 计算 PS 的长度
    ps_len = k - m_len - 3

    # 生成 PS (随机非零字节)
    ps = b''
    while len(ps) < ps_len:
        # 使用 os.urandom 生成高质量随机字节
        random_bytes = os.urandom(ps_len - len(ps))
        # 过滤掉 0x00 字节
        ps += bytes(b for b in random_bytes if b != 0)

    # 构建填充后的消息 EM
    em = b'\x00\x02' + ps + b'\x00' + message_bytes

    return em

def unpad_pkcs1_v1_5(padded_bytes):
    """移除 PKCS#1 v1.5 (Type 2) 填充, 还原原始消息.

    Args:
        padded_bytes (bytes): 经过填充的消息字节串。

    Returns:
        bytes: 原始消息字节串。

    Raises:
        ValueError: 如果填充格式不正确。
    """
    k = len(padded_bytes)

    # 检查基本格式和长度
    if k < 11:
        raise ValueError("填充数据太短, 不可能是有效的 PKCS#1 v1.5 格式")

    if padded_bytes[0] != 0x00:
        raise ValueError("填充错误: 第一个字节不是 0x00")

    if padded_bytes[1] != 0x02:
        raise ValueError("填充错误: 第二个字节不是 0x02 (不是加密块)")

    # 寻找 0x00 分隔符
    sep_index = -1
    for i in range(2, k):
        if padded_bytes[i] == 0x00:
            sep_index = i
            break

    if sep_index == -1:
        raise ValueError("填充错误: 未找到 0x00 分隔符")

    # 检查 PS 长度
    ps_len = sep_index - 2
    if ps_len < 8:
        raise ValueError(f"填充错误: 填充字符串 (PS) 长度 {ps_len} 小于 8")

    # 提取原始消息 M
    message_bytes = padded_bytes[sep_index + 1:]

    return message_bytes

# ---------------------------------------------------------------
# 模块四: 加密与解密
# ---------------------------------------------------------------

def encrypt(message_bytes, public_key):
    """使用公钥和 PKCS#1 v1.5 填充来加密消息 (单块).

    Args:
        message_bytes (bytes): 要加密的原始消息字节串。
        public_key (tuple): 公钥 (e, N)。

    Returns:
        bytes: 加密后的密文字节串。

    Raises:
        ValueError: 如果消息太长无法填充。
    """
    e, N = public_key
    k = _get_byte_length(N)

    print(f"    正在加密 (N 位数: {_get_byte_length(N)*8}, k: {k})...")

    # 1. 填充消息
    print(f"    1. 正在填充消息 (长度: {len(message_bytes)})...")
    try:
        padded_m_bytes = pad_pkcs1_v1_5(message_bytes, N)
        print(f"       填充后长度: {len(padded_m_bytes)}")
    except ValueError as e:
        print(f"       填充失败: {e}")
        raise e

    # 2. 字节转整数
    print("    2. 正在将填充字节转换为整数...")
    m = _bytes_to_int(padded_m_bytes)

    # 3. RSA 加密: c = m^e mod N
    print("    3. 正在执行 RSA 模幂运算 (加密)...")
    c = pow(m, e, N)
    print("       模幂运算完成。")

    # 4. 整数转字节 (长度必须为 k)
    print(f"    4. 正在将密文整数转换为 {k} 字节...")
    ciphertext_bytes = _int_to_bytes(c, k)

    print("    加密完成。")
    return ciphertext_bytes

def decrypt(ciphertext_bytes, private_key):
    """使用私钥和 PKCS#1 v1.5 填充来解密消息 (单块).

    Args:
        ciphertext_bytes (bytes): 要解密的密文字节串。
        private_key (tuple): 私钥 (d, N)。

    Returns:
        bytes: 解密后的原始消息字节串。

    Raises:
        ValueError: 如果密文长度不匹配或填充无效。
    """
    d, N = private_key
    k = _get_byte_length(N)

    print(f"    正在解密 (N 位数: {_get_byte_length(N)*8}, k: {k})...")

    # 检查密文长度是否等于 k
    if len(ciphertext_bytes) != k:
        raise ValueError(f"密文长度 ({len(ciphertext_bytes)}) 与密钥长度 ({k}) 不匹配")

    # 1. 字节转整数
    print(f"    1. 正在将 {len(ciphertext_bytes)} 字节密文转换为整数...")
    c = _bytes_to_int(ciphertext_bytes)

    # 2. RSA 解密: m = c^d mod N
    print("    2. 正在执行 RSA 模幂运算 (解密)...")
    m = pow(c, d, N)
    print("       模幂运算完成。")

    # 3. 整数转字节 (长度必须为 k)
    print(f"    3. 正在将明文整数转换为 {k} 字节...")
    padded_m_bytes = _int_to_bytes(m, k)

    # 4. 去填充
    print("    4. 正在移除 PKCS#1 v1.5 填充...")
    try:
        message_bytes = unpad_pkcs1_v1_5(padded_m_bytes)
        print("       去填充完成。")
    except ValueError as e:
        print(f"       去填充失败: {e}")
        raise e

    print("    解密完成。")
    return message_bytes

# ---------------------------------------------------------------
# 模块五: PEM 与 DER 编码
# ---------------------------------------------------------------
def _der_encode_length(length):
    """根据 DER 规则编码长度.

    Args:
        length (int): 要编码的长度值.

    Returns:
        bytes: 编码后的长度字节串.
    """
    if length < 128:
        # 短格式: 直接返回长度值 (1 字节)
        return length.to_bytes(1, 'big')
    else:
        # 长格式
        # 1. 计算表示 length 需要多少字节
        length_bytes = _int_to_bytes(length) # 使用我们之前的辅助函数
        num_length_bytes = len(length_bytes)

        # 2. 第一个字节是 0x80 | num_length_bytes
        first_byte = (0x80 | num_length_bytes).to_bytes(1, 'big')

        # 3. 返回 first_byte + length_bytes
        return first_byte + length_bytes

def _der_encode_integer(n):
    """根据 DER 规则编码整数.

    Args:
        n (int): 要编码的整数.

    Returns:
        bytes: 编码后的 DER 整数 (包含 Type 和 Length).
    """
    # Type 字节
    type_byte = b'\x02'

    # 1. 将整数转换为字节
    value_bytes = _int_to_bytes(n)

    # 2. 检查最高位, 如果是 1, 且不是单个 0x00, 则补 0x00
    if value_bytes[0] & 0x80: # 检查最高位是否为 1
         value_bytes = b'\x00' + value_bytes

    # 3. 编码长度
    length_bytes = _der_encode_length(len(value_bytes))

    # 4. 拼接 Type + Length + Value
    return type_byte + length_bytes + value_bytes

def _der_encode_sequence(der_elements):
    """根据 DER 规则编码一个序列.

    Args:
        der_elements (list[bytes]): 一个包含已 DER 编码的元素的列表.

    Returns:
        bytes: 编码后的 DER 序列 (包含 Type 和 Length).
    """
    # Type 字节
    type_byte = b'\x30'

    # 1. 拼接所有元素
    concatenated_elements = b''.join(der_elements)

    # 2. 编码总长度
    length_bytes = _der_encode_length(len(concatenated_elements))

    # 3. 拼接 Type + Length + Value
    return type_byte + length_bytes + concatenated_elements

def _calculate_pkcs1_components(d, p, q):
    """计算 PKCS#1 私钥所需的额外组件.

    Args:
        d (int): 私钥指数.
        p (int): 第一个素数.
        q (int): 第二个素数.

    Returns:
        tuple: (exponent1, exponent2, coefficient).
    """
    exponent1 = d % (p - 1)
    exponent2 = d % (q - 1)
    coefficient = modinv(q, p) # 需要我们的 modinv 函数
    return (exponent1, exponent2, coefficient)

# ---------------------------------------------------------------
# 构建 PEM 格式
# ---------------------------------------------------------------

def save_pem_private_key(public_key, private_key, p, q, filename):
    """将 RSA 私钥以 PKCS#1 PEM 格式保存到文件.

    Args:
        public_key (tuple): 公钥 (e, N).
        private_key (tuple): 私钥 (d, N).
        p (int): 第一个素数.
        q (int): 第二个素数.
        filename (str): 要保存的文件名.

    Raises:
        ValueError: 如果公钥和私钥的 N 不匹配.
        IOError: 如果文件写入失败.
    """
    e, N = public_key
    d, N_priv = private_key

    # 确认 N 匹配
    if N != N_priv:
        raise ValueError("公钥和私钥中的 N 不匹配 (N in public and private keys do not match).")

    print(f"正在准备保存私钥到 {filename}.")

    # 1. 计算 PKCS#1 额外组件
    print("    1. 正在计算 exponent1, exponent2, coefficient.")
    exponent1, exponent2, coefficient = _calculate_pkcs1_components(d, p, q)

    # 2. 定义版本号 (双素数 RSA 为 0)
    version = 0

    # 3. 按 PKCS#1 顺序排列所有组件
    components = [
        version, N, e, d, p, q,
        exponent1, exponent2, coefficient
    ]

    # 4. DER 编码所有整数组件
    print("    2. 正在对所有组件进行 DER (INTEGER) 编码.")
    der_components = [_der_encode_integer(comp) for comp in components]

    # 5. DER 编码整个序列
    print("    3. 正在对组件列表进行 DER (SEQUENCE) 编码.")
    der_sequence = _der_encode_sequence(der_components)

    # 6. Base64 编码
    print("    4. 正在进行 Base64 编码.")
    pem_data_base64 = base64.b64encode(der_sequence)

    # 7. 格式化 Base64 (每行 64 字符)
    print("    5. 正在格式化 Base64 输出.")
    pem_lines = []
    chunk_size = 64
    for i in range(0, len(pem_data_base64), chunk_size):
        pem_lines.append(pem_data_base64[i:i+chunk_size].decode('ascii'))
    pem_formatted = "\n".join(pem_lines)

    # 8. 构建 PEM 字符串
    pem_string = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        f"{pem_formatted}\n"
        "-----END RSA PRIVATE KEY-----\n"
    )

    # 9. 写入文件
    print(f"    6. 正在将 PEM 字符串写入文件 {filename}.")
    try:
        with open(filename, 'w') as f:
            f.write(pem_string)
        print(f"✅ 私钥已成功保存到 {filename}.")
    except IOError as e:
        print(f"❌ 写入文件时发生错误: {e}")
        raise e

def save_pem_public_key(public_key, filename):
    """将 RSA 公钥以 PKCS#1 PEM 格式保存到文件.

    Args:
        public_key (tuple): 公钥 (e, N).
        filename (str): 要保存的文件名.

    Raises:
        IOError: 如果文件写入失败.
    """
    e, N = public_key

    print(f"正在准备保存公钥到 {filename}.")

    # 1. 按 PKCS#1 顺序排列组件 (N, e)
    components = [N, e]

    # 2. DER 编码所有整数组件
    print("    1. 正在对 N 和 e 进行 DER (INTEGER) 编码.")
    der_components = [_der_encode_integer(comp) for comp in components]

    # 3. DER 编码整个序列
    print("    2. 正在对组件列表进行 DER (SEQUENCE) 编码.")
    der_sequence = _der_encode_sequence(der_components)

    # 4. Base64 编码
    print("    3. 正在进行 Base64 编码.")
    pem_data_base64 = base64.b64encode(der_sequence)

    # 5. 格式化 Base64 (每行 64 字符)
    print("    4. 正在格式化 Base64 输出.")
    pem_lines = []
    chunk_size = 64
    for i in range(0, len(pem_data_base64), chunk_size):
        pem_lines.append(pem_data_base64[i:i+chunk_size].decode('ascii'))
    pem_formatted = "\n".join(pem_lines)

    # 6. 构建 PEM 字符串 (注意头尾是 'RSA PUBLIC KEY')
    pem_string = (
        "-----BEGIN RSA PUBLIC KEY-----\n"
        f"{pem_formatted}\n"
        "-----END RSA PUBLIC KEY-----\n"
    )

    # 7. 写入文件
    print(f"    5. 正在将 PEM 字符串写入文件 {filename}.")
    try:
        with open(filename, 'w') as f:
            f.write(pem_string)
        print(f"✅ 公钥已成功保存到 {filename}.")
    except IOError as e:
        print(f"❌ 写入文件时发生错误: {e}")
        raise e

# ---------------------------------------------------------------
# 模块六: 长消息/文件处理
# ---------------------------------------------------------------

def encrypt_large(message_bytes, public_key):
    """使用公钥加密长消息 (自动分块).

    Args:
        message_bytes (bytes): 要加密的原始消息字节串.
        public_key (tuple): 公钥 (e, N).

    Returns:
        bytes: 加密后的完整密文字节串.

    Raises:
        ValueError: 如果密钥太小无法容纳任何数据.
    """
    e, N = public_key
    k = _get_byte_length(N)
    max_chunk_size = k - 11

    # 检查密钥是否至少能容纳 1 字节数据 + 11 字节填充
    if max_chunk_size <= 0:
        raise ValueError("密钥太小, 无法容纳 PKCS#1 v1.5 填充.")

    print(f"    开始长消息加密 (明文块最大: {max_chunk_size}, 密文块: {k})...")
    encrypted_chunks = []

    # 按 max_chunk_size 分块
    for i in range(0, len(message_bytes), max_chunk_size):
        chunk = message_bytes[i:i+max_chunk_size]
        print(f"        正在加密块 {i // max_chunk_size + 1} (大小: {len(chunk)})...")
        # 调用单块加密函数 (它会进行填充)
        encrypted_chunks.append(encrypt(chunk, public_key))

    print("    长消息加密完成.")
    # 将所有加密后的 k 字节块拼接起来
    return b"".join(encrypted_chunks)

def decrypt_large(ciphertext_bytes, private_key):
    """使用私钥解密长消息 (自动分块).

    Args:
        ciphertext_bytes (bytes): 要解密的密文字节串.
        private_key (tuple): 私钥 (d, N).

    Returns:
        bytes: 解密后的原始消息字节串.

    Raises:
        ValueError: 如果密文长度不是 k 的整数倍.
    """
    d, N = private_key
    k = _get_byte_length(N)

    # 密文必须是 k 的整数倍
    if len(ciphertext_bytes) % k != 0:
        raise ValueError("密文长度不是密钥字节长度 (k) 的整数倍, 可能已损坏.")

    print(f"    开始长消息解密 (密文块: {k})...")
    decrypted_chunks = []

    # 按 k 分块
    for i in range(0, len(ciphertext_bytes), k):
        chunk = ciphertext_bytes[i:i+k]
        print(f"        正在解密块 {i // k + 1}...")
        # 调用单块解密函数 (它会进行去填充)
        decrypted_chunks.append(decrypt(chunk, private_key))

    print("    长消息解密完成.")
    # 将所有解密后的明文块拼接起来
    return b"".join(decrypted_chunks)

def encrypt_file(input_filename, output_filename, public_key):
    """加密文件.

    Args:
        input_filename (str): 输入文件名 (明文).
        output_filename (str): 输出文件名 (密文).
        public_key (tuple): 公钥 (e, N).
    """
    print(f"开始加密文件: {input_filename} -> {output_filename}")
    try:
        # 以二进制模式读取 ('rb')
        with open(input_filename, 'rb') as f_in:
            message_bytes = f_in.read()

        print(f"    读取文件 {input_filename} ({len(message_bytes)} 字节).")
        encrypted_bytes = encrypt_large(message_bytes, public_key)

        # 以二进制模式写入 ('wb')
        with open(output_filename, 'wb') as f_out:
            f_out.write(encrypted_bytes)

        print(f"✅ 文件加密成功: {output_filename} ({len(encrypted_bytes)} 字节).")

    except FileNotFoundError:
        print(f"❌ 错误: 输入文件 {input_filename} 未找到.")
    except Exception as e:
        print(f"❌ 文件加密过程中发生错误: {e}")
        raise e

def decrypt_file(input_filename, output_filename, private_key):
    """解密文件.

    Args:
        input_filename (str): 输入文件名 (密文).
        output_filename (str): 输出文件名 (明文).
        private_key (tuple): 私钥 (d, N).
    """
    print(f"开始解密文件: {input_filename} -> {output_filename}")
    try:
        # 以二进制模式读取 ('rb')
        with open(input_filename, 'rb') as f_in:
            ciphertext_bytes = f_in.read()

        print(f"    读取文件 {input_filename} ({len(ciphertext_bytes)} 字节).")
        decrypted_bytes = decrypt_large(ciphertext_bytes, private_key)

        # 以二进制模式写入 ('wb')
        with open(output_filename, 'wb') as f_out:
            f_out.write(decrypted_bytes)

        print(f"✅ 文件解密成功: {output_filename} ({len(decrypted_bytes)} 字节).")

    except FileNotFoundError:
        print(f"❌ 错误: 输入文件 {input_filename} 未找到.")
    except Exception as e:
        print(f"❌ 文件解密过程中发生错误: {e}")
        raise e

# ---------------------------------------------------------------
# 模块七: PEM 与 DER 解析 (加载)
# ---------------------------------------------------------------

def _der_parse_length(der_bytes, offset):
    """从指定偏移量开始解析 DER 长度.

    Args:
        der_bytes (bytes): 包含 DER 数据的字节串.
        offset (int): 当前解析的起始偏移量.

    Returns:
        tuple: (length, value_offset), 其中 length 是值的长度,
               value_offset 是值部分的起始偏移量.

    Raises:
        ValueError: 如果 DER 格式不正确.
    """
    len_byte = der_bytes[offset]
    offset += 1

    if len_byte < 128:
        # 短格式: 长度就是这个字节的值
        length = len_byte
    else:
        # 长格式: 第一个字节表示长度本身占多少字节
        num_len_bytes = len_byte & 0x7F # 去掉最高位的 1

        if num_len_bytes == 0:
            # 0x80 表示不定长格式, 我们这里不支持, 因为 PKCS#1 是定长的.
            raise ValueError("不支持不定长 DER 格式 (Indefinite length form not supported).")

        if offset + num_len_bytes > len(der_bytes):
            raise ValueError("DER 长度字节超出数据范围.")

        # 读取表示长度的字节, 并转换为整数
        length = _bytes_to_int(der_bytes[offset : offset + num_len_bytes])
        offset += num_len_bytes

    return length, offset

def _der_parse_integer(der_bytes, offset):
    """从指定偏移量开始解析一个 DER 整数.

    Args:
        der_bytes (bytes): 包含 DER 数据的字节串.
        offset (int): 当前解析的起始偏移量.

    Returns:
        tuple: (integer_value, next_offset), 其中 integer_value 是解析出的整数,
               next_offset 是下一个元素的起始偏移量.

    Raises:
        ValueError: 如果 DER 格式不正确或不是 INTEGER.
    """
    original_offset = offset

    # 检查 Type 字节是否为 0x02 (INTEGER)
    if der_bytes[offset] != 0x02:
        raise ValueError(f"期望 DER INTEGER (0x02) 但在偏移量 {offset} 处找到 {der_bytes[offset]:02x}.")
    offset += 1

    # 解析长度和值的起始偏移量
    length, offset = _der_parse_length(der_bytes, offset)

    # 检查值的长度是否超出范围
    if offset + length > len(der_bytes):
        raise ValueError(f"DER INTEGER 值 (长度 {length}) 超出数据范围 (起始于 {original_offset}).")

    # 提取值的字节串并转换为整数
    value_bytes = der_bytes[offset : offset + length]
    integer_value = _bytes_to_int(value_bytes)

    # 更新偏移量到下一个元素
    offset += length

    return integer_value, offset

def _der_parse_sequence(der_bytes, offset):
    """从指定偏移量开始解析一个 DER 序列.

    此实现假设序列中只包含整数, 这适用于 PKCS#1 密钥格式.

    Args:
        der_bytes (bytes): 包含 DER 数据的字节串.
        offset (int): 当前解析的起始偏移量.

    Returns:
        tuple: (elements_list, next_offset), 其中 elements_list 是解析出的元素列表,
               next_offset 是下一个元素的起始偏移量.

    Raises:
        ValueError: 如果 DER 格式不正确或不是 SEQUENCE.
    """
    original_offset = offset

    # 检查 Type 字节是否为 0x30 (SEQUENCE)
    if der_bytes[offset] != 0x30:
        raise ValueError(f"期望 DER SEQUENCE (0x30) 但在偏移量 {offset} 处找到 {der_bytes[offset]:02x}.")
    offset += 1

    # 解析序列的总长度和内容起始偏移量
    seq_length, offset = _der_parse_length(der_bytes, offset)

    # 确定序列内容的结束偏移量
    end_offset = offset + seq_length

    # 检查序列长度是否超出范围
    if end_offset > len(der_bytes):
        raise ValueError(f"DER SEQUENCE (长度 {seq_length}) 超出数据范围 (起始于 {original_offset}).")

    elements = []

    # 循环解析序列中的每个元素, 直到到达结束偏移量
    while offset < end_offset:
        # 假设序列中都是整数, 调用整数解析器
        element_val, next_off = _der_parse_integer(der_bytes, offset)
        elements.append(element_val)
        offset = next_off

    # 确保我们正好解析完整个序列的内容
    if offset != end_offset:
        raise ValueError("DER 序列内容长度与声明的长度不匹配.")

    return elements, offset

def _read_pem_and_decode_base64(filename, expected_header, expected_footer):
    """读取 PEM 文件, 提取 Base64 内容并解码为 DER 字节串.

    Args:
        filename (str): PEM 文件名.
        expected_header (str): 期望的 PEM 文件头.
        expected_footer (str): 期望的 PEM 文件尾.

    Returns:
        bytes: 解码后的 DER 字节串.

    Raises:
        FileNotFoundError: 如果文件未找到.
        ValueError: 如果 PEM 格式无效或 Base64 解码失败.
        IOError: 如果读取文件时发生其他错误.
    """
    print(f"    正在读取 PEM 文件: {filename}.")
    try:
        with open(filename, 'r') as f:
            content = f.read()
    except FileNotFoundError:
        raise FileNotFoundError(f"PEM 文件 {filename} 未找到.")
    except Exception as e:
        raise IOError(f"读取 PEM 文件 {filename} 时发生错误: {e}")

    # 查找 PEM 头尾
    header_pos = content.find(expected_header)
    footer_pos = content.find(expected_footer)

    if header_pos == -1 or footer_pos == -1 or footer_pos < header_pos:
        raise ValueError(f"无效的 PEM 文件格式: 未找到 '{expected_header}' 或 '{expected_footer}'.")

    # 提取 Base64 部分 (去掉头尾和空白)
    base64_start = header_pos + len(expected_header)
    base64_end = footer_pos
    base64_data = content[base64_start:base64_end].strip()

    # 清理 Base64 数据 (移除换行符等非 Base64 字符)
    base64_cleaned = re.sub(r'[^A-Za-z0-9+/=]', '', base64_data)
    print(f"    提取并清理 Base64 数据.")

    # Base64 解码
    try:
        der_bytes = base64.b64decode(base64_cleaned)
        print(f"    Base64 解码成功, 得到 {len(der_bytes)} 字节的 DER 数据.")
        return der_bytes
    except binascii.Error as e:
        raise ValueError(f"Base64 解码失败: {e}")

def load_pem_private_key(filename):
    """从 PEM 文件加载 RSA 私钥 (PKCS#1 格式).

    Args:
        filename (str): 私钥 PEM 文件名.

    Returns:
        tuple: ((e, N), (d, N), p, q), 包含公钥, 私钥, p 和 q.

    Raises:
        各种异常 (FileNotFoundError, ValueError, IOError).
    """
    print(f"开始加载私钥从 {filename}.")
    header = "-----BEGIN RSA PRIVATE KEY-----"
    footer = "-----END RSA PRIVATE KEY-----"

    der_bytes = _read_pem_and_decode_base64(filename, header, footer)

    print("    正在解析 DER 序列.")
    try:
        components, next_offset = _der_parse_sequence(der_bytes, 0)
    except ValueError as e:
        raise ValueError(f"DER 解析失败: {e}")

    if len(der_bytes) != next_offset:
        print(f"警告: DER 数据末尾有多余字节 ({len(der_bytes)} vs {next_offset}).")

    if len(components) != 9:
        raise ValueError(f"期望 9 个 PKCS#1 私钥组件, 但解析出 {len(components)} 个.")

    version, N, e, d, p, q, exponent1, exponent2, coefficient = components

    if version != 0:
        print(f"警告: 私钥版本号为 {version}, 而非预期的 0.")

    print("✅ 私钥加载成功.")
    return ((e, N), (d, N), p, q)

def load_pem_public_key(filename):
    """从 PEM 文件加载 RSA 公钥 (PKCS#1 格式).

    Args:
        filename (str): 公钥 PEM 文件名.

    Returns:
        tuple: 公钥 (e, N).

    Raises:
        各种异常 (FileNotFoundError, ValueError, IOError).
    """
    print(f"开始加载公钥从 {filename}.")
    header = "-----BEGIN RSA PUBLIC KEY-----"
    footer = "-----END RSA PUBLIC KEY-----"

    der_bytes = _read_pem_and_decode_base64(filename, header, footer)

    print("    正在解析 DER 序列.")
    try:
        components, next_offset = _der_parse_sequence(der_bytes, 0)
    except ValueError as e:
        raise ValueError(f"DER 解析失败: {e}")

    if len(der_bytes) != next_offset:
         print(f"警告: DER 数据末尾有多余字节 ({len(der_bytes)} vs {next_offset}).")

    if len(components) != 2:
        raise ValueError(f"期望 2 个 PKCS#1 公钥组件 (N, e), 但解析出 {len(components)} 个.")

    N, e = components

    print("✅ 公钥加载成功.")
    return (e, N)


# ---------------------------------------------------------------
# 测试代码块
# ---------------------------------------------------------------

if __name__ == "__main__":
  # 为了快速测试, 我们选择一个较小的位数, 比如 128 位。
  # 实际应用至少需要 2048 位。
  bits_to_test = 2048  # <--- 修改这里可以测试不同位数

  try:
    public_key, private_key, p, q = generate_key_pair(bits_to_test)
    e, N = public_key
    d, N_priv = private_key # N_priv 应该和 N 相等

    print("\n--- 密钥生成结果 ---")
    print(f"密钥位数: {bits_to_test}")
    print(f"公钥 (e): {e}")
    print(f"公钥/私钥 (N): {N}")
    print(f"私钥 (d): {d}")
    print(f"N 的实际位数: {N.bit_length()}")

  except Exception as e:
    print(f"\n发生错误: {e}")

  # --- 测试加密与解密 ---
  print("\n--- 测试加密与解密 ---")
  # 注意: 确保消息不要太长, 以至于超过 k-11 字节
  # 对于 128 位密钥 (k=16), 最大长度是 16-11 = 5 字节.
  # 对于 512 位密钥 (k=64), 最大长度是 64-11 = 53 字节.
  # 我们用 UTF-8 编码, 一个中文字符通常占 3 字节。
  message = "你好 RSA!" # 3*3 + 5 = 14 字节 (对于 128 位密钥可能太长, 建议测试时用 512 位或更大)

  # 如果用 128 位测试, 请用短消息, 如:
  # message = "Hi!"

  print(f"原始消息: {message}")
  message_bytes = message.encode('utf-8')
  print(f"原始字节 (UTF-8, 长度 {len(message_bytes)}): {message_bytes}")

  # 检查消息长度是否适合当前密钥位数
  k_test = _get_byte_length(N)
  if len(message_bytes) > k_test - 11:
    print(f"警告: 消息长度 {len(message_bytes)} 可能超过 {bits_to_test} 位密钥的最大限制 ({k_test - 11})。")
    print("如果加密失败, 请尝试使用更长的密钥或更短的消息。")
    # 可以选择在这里退出或继续尝试
    # sys.exit(1)

  try:
    # 加密
    encrypted_bytes = encrypt(message_bytes, public_key)
    print(f"\n加密后字节 (长度 {len(encrypted_bytes)})")
    # 使用 Base64 编码方便显示和传输
    encrypted_base64 = base64.b64encode(encrypted_bytes)
    print(f"加密后 (Base64): {encrypted_base64.decode('ascii')}")

    # 解密
    decrypted_bytes = decrypt(encrypted_bytes, private_key)
    print(f"\n解密后字节 (长度 {len(decrypted_bytes)}): {decrypted_bytes}")
    decrypted_message = decrypted_bytes.decode('utf-8')
    print(f"解密后消息: {decrypted_message}")

    # 验证
    print("\n--- 验证 ---")
    if message == decrypted_message:
        print("✅ 验证成功: 加密 -> 解密 -> 原始消息一致!")
    else:
        print("❌ 验证失败!")

  except ValueError as ve:
    print(f"\n❌ 加解密过程中发生错误: {ve}")

  # --- 测试保存 PEM ---
  print("\n--- 测试保存 PEM ---")
  pem_filename = "private_key.pem"
  try:
    # 确保 p 和 q 已经从 generate_key_pair 获得
    save_pem_private_key(public_key, private_key, p, q, pem_filename)
    print(f"    请检查当前目录下是否生成了 {pem_filename} 文件.")
  except Exception as e:
    print(f"    ❌ 保存 PEM 时发生错误: {e}")

  # --- 测试保存公钥 PEM ---
  print("\n--- 测试保存公钥 PEM ---")
  pub_pem_filename = "public_key.pem"
  try:
    save_pem_public_key(public_key, pub_pem_filename)
    print(f"    请检查当前目录下是否生成了 {pub_pem_filename} 文件.")
  except Exception as e:
    print(f"    ❌ 保存公钥 PEM 时发生错误: {e}")

  # --- 测试文件加解密 ---
  print("\n--- 测试文件加解密 ---")
  # 1. 创建一个测试文件
  test_filename_plain = "test_plain.txt"
  test_filename_enc = "test_encrypted.enc"
  test_filename_dec = "test_decrypted.txt"
  test_content = "这是用于测试长消息和文件加解密的一段文本. " * 10
  # 重复 10 次使其变长, 确保会分块 (根据密钥大小)

  try:
    print(f"    1. 创建测试文件 {test_filename_plain}...")
    with open(test_filename_plain, 'w', encoding='utf-8') as f:
      f.write(test_content)

    # 2. 加密文件
    print(f"\n    2. 正在加密文件...")
    encrypt_file(test_filename_plain, test_filename_enc, public_key)

    # 3. 解密文件
    print(f"\n    3. 正在解密文件...")
    decrypt_file(test_filename_enc, test_filename_dec, private_key)

    # 4. 验证内容
    print(f"\n    4. 正在验证内容...")
    with open(test_filename_dec, 'r', encoding='utf-8') as f:
      decrypted_content = f.read()

    if test_content == decrypted_content:
      print("✅ 文件加解密验证成功!")
    else:
      print("❌ 文件加解密验证失败!")
      print(f"       原始长度: {len(test_content)}")
      print(f"       解密长度: {len(decrypted_content)}")

  except Exception as e:
    print(f"    ❌ 文件测试过程中发生错误: {e}")
  finally:
    # (可选) 清理测试文件
    # import os
    # if os.path.exists(test_filename_plain): os.remove(test_filename_plain)
    # if os.path.exists(test_filename_enc): os.remove(test_filename_enc)
    # if os.path.exists(test_filename_dec): os.remove(test_filename_dec)
    pass

  # --- 测试加载 PEM ---
  print("\n--- 测试加载 PEM ---")
  try:
    print("    正在加载公钥...")
    loaded_public_key = load_pem_public_key(pub_pem_filename)
    print(f"    加载的公钥 e: {loaded_public_key[0]}")
    print(f"    加载的公钥 N (部分): {str(loaded_public_key[1])[:20]}...")

    # 比较原始公钥和加载的公钥
    if public_key == loaded_public_key:
      print("    ✅ 加载的公钥与原始公钥一致.")
    else:
      print("    ❌ 加载的公钥与原始公钥不一致.")

    print("\n    正在加载私钥...")
    loaded_pub, loaded_priv, loaded_p, loaded_q = load_pem_private_key(pem_filename)
    print(f"    加载的私钥 d (部分): {str(loaded_priv[0])[:20]}...")

    # 比较原始私钥和加载的私钥 (只比较 d 和 N)
    if private_key == loaded_priv and p == loaded_p and q == loaded_q:
      print("    ✅ 加载的私钥与原始私钥一致.")
    else:
      print("    ❌ 加载的私钥与原始私钥不一致.")

    # (可选) 使用加载的密钥进行一次加解密测试
    print("\n    使用加载的密钥进行测试:")
    encrypted_again = encrypt(message_bytes, loaded_public_key)
    decrypted_again = decrypt(encrypted_again, loaded_priv)
    if message_bytes == decrypted_again:
      print("    ✅ 使用加载的密钥进行加解密成功.")
    else:
      print("    ❌ 使用加载的密钥进行加解密失败.")

  except Exception as e:
    print(f"    ❌ 加载 PEM 或使用加载密钥时发生错误: {e}")