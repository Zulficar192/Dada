#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
加密算法模块
"""

import os
import time
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


class Encryptor:
    """加密器类"""
    
    def __init__(self):
        self.backend = default_backend()
        import hashlib
        self.hash_lib = hashlib
    
    def generate_file_fingerprint(self, data: bytes, creation_time: float = None, machine_id: str = "", file_path: str = "") -> str:
        """
        生成文件唯一指纹
        
        Args:
            data: 文件内容
            creation_time: 创建时间戳
            machine_id: 机器唯一标识符
            file_path: 文件路径，用于防复制
            
        Returns:
            唯一指纹字符串
        """
        # 使用当前时间作为默认创建时间
        if creation_time is None:
            creation_time = time.time()
        
        # 确保creation_time的精度一致
        creation_time = round(creation_time, 6)
        
        # 使用文件内容、创建时间、机器ID、文件路径的组合生成指纹
        # 不再使用固定种子，而是使用更复杂的组合方式
        fingerprint_data = (
            f"FILE_FINGERPRINT_V2".encode() +  # 版本标识
            data +  # 文件内容
            f"|{creation_time}".encode() +  # 创建时间
            f"|{machine_id}".encode() +  # 机器ID
            f"|{file_path}".encode()  # 文件路径
        )
        
        # 使用SHA-256生成指纹，重复计算两次增加安全性
        fingerprint = self.hash_lib.sha256(fingerprint_data).digest()
        fingerprint = self.hash_lib.sha256(fingerprint).hexdigest()
        
        return fingerprint
    
    def generate_key(self, password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """
        从密码生成密钥，使用PBKDF2和随机盐值
        
        Args:
            password: 密码字符串
            salt: 盐值，None则生成随机盐
            
        Returns:
            (密钥字节, 盐值字节)
        """
        # 生成随机盐值
        if salt is None:
            salt = os.urandom(16)
        
        # 使用PBKDF2进行密钥派生，迭代次数设为100000次
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        
        # 生成32字节密钥（AES-256）
        key = kdf.derive(password.encode('utf-8'))
        
        return key, salt
    
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """
        单次加密
        
        Args:
            data: 要加密的数据
            key: 加密密钥
            
        Returns:
            加密后的数据，格式：salt(16字节) + iv(16字节) + 加密数据
        """
        # 生成随机IV
        iv = os.urandom(16)
        
        # 创建AES加密器
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # 对数据进行填充
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        
        # 加密数据
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # 返回IV + 加密数据（盐值在嵌套加密中处理）
        return iv + encrypted_data
    
    def decrypt(self, encrypted_data: bytes, key: bytes) -> bytes:
        """
        单次解密
        
        Args:
            encrypted_data: 加密后的数据，格式：iv(16字节) + 加密数据
            key: 解密密钥
            
        Returns:
            解密后的数据
        """
        # 确保数据长度至少包含IV
        if len(encrypted_data) < 16:
            raise ValueError("加密数据长度不足，无法提取IV")
        
        # 提取IV
        iv = encrypted_data[:16]
        data = encrypted_data[16:]
        
        # 创建AES解密器
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # 解密数据
        padded_data = decryptor.update(data) + decryptor.finalize()
        
        # 移除填充
        unpadder = padding.PKCS7(128).unpadder()
        original_data = unpadder.update(padded_data) + unpadder.finalize()
        
        return original_data
    
    def nested_encrypt(self, data: bytes, keys: list, original_extension: str = "", max_attempts: int = 3, machine_id: str = "", file_path: str = "") -> bytes:
        """
        多层嵌套加密
        
        Args:
            data: 要加密的数据
            keys: 密钥列表，从外层到内层
            original_extension: 原始文件扩展名
            max_attempts: 最大失败尝试次数
            machine_id: 机器唯一标识符
            file_path: 文件路径，用于防复制
            
        Returns:
            多层加密后的数据，包含元数据头
        """
        # 获取当前时间作为创建时间
        creation_time = time.time()
        
        # 生成文件唯一指纹，使用原始数据、创建时间、机器ID和文件路径
        fingerprint = self.generate_file_fingerprint(data, creation_time, machine_id, file_path)
        
        # 执行多层加密
        encrypted_data = data
        salt_values = []  # 保存每层加密的盐值
        for password in keys:
            key, salt = self.generate_key(password)
            encrypted_data = self.encrypt(encrypted_data, key)
            salt_values.append(salt)  # 保存当前层的盐值
        
        # 将盐值转换为十六进制字符串，用逗号分隔
        salt_string = ",".join([salt.hex() for salt in salt_values])
        
        # 构建元数据头
        # 格式: MAGIC|ORIG_EXT|MAX_ATTEMPTS|FAILED_ATTEMPTS|SELF_DESTRUCT|FINGERPRINT|CREATION_TIME|SALT_VALUES|
        magic = "ENCRYPTED_FILE"  # 魔术字符串
        original_extension = original_extension.ljust(10, " ")  # 固定10字节
        max_attempts = str(max_attempts).zfill(3)  # 固定3字节
        failed_attempts = "000"  # 固定3字节，初始0
        self_destruct = "0"  # 固定1字节，0=正常，1=已销毁
        fingerprint = fingerprint[:32]  # 使用前32字节，固定32字节
        creation_time_str = f"{creation_time:.6f}".ljust(20, " ")  # 固定20字节，包含小数点
        salt_values_field = salt_string.ljust(200, " ")  # 增加盐值字段长度到200字节，支持更多加密层级
        
        # 构建元数据头
        header = f"{magic}|{original_extension}|{max_attempts}|{failed_attempts}|{self_destruct}|{fingerprint}|{creation_time_str}|{salt_values_field}|"
        
        # 返回带元数据头的加密数据
        return header.encode() + encrypted_data
    
    def parse_metadata(self, encrypted_data: bytes) -> dict:
        """
        解析加密数据中的元数据
        
        Args:
            encrypted_data: 加密后的数据
            
        Returns:
            元数据字典
        """
        # 检查魔术字符串
        if not encrypted_data.startswith(b"ENCRYPTED_FILE|"):
            raise ValueError("无效的加密文件格式")
        
        # 查找元数据头结束位置
        # 格式: MAGIC|ORIG_EXT|MAX_ATTEMPTS|FAILED_ATTEMPTS|SELF_DESTRUCT|FINGERPRINT|CREATION_TIME|SALT_VALUES|
        # 我们需要找到第8个"|"作为元数据头的结束
        magic_len = len("ENCRYPTED_FILE|")
        header_end = magic_len
        separator_count = 0
        
        # 查找第8个"|"（因为元数据头包含8个分隔符）
        for i in range(magic_len, len(encrypted_data)):
            if encrypted_data[i:i+1] == b"|":
                separator_count += 1
                if separator_count == 7:  # 第8个字段结束
                    header_end = i + 1
                    break
        
        if separator_count < 7:
            raise ValueError("无效的元数据格式")
        
        # 解析元数据头
        header = encrypted_data[:header_end].decode()
        parts = header.split("|")
        
        if len(parts) != 9:
            raise ValueError("无效的元数据格式")
        
        return {
            "magic": parts[0],
            "original_extension": parts[1].strip(),
            "max_attempts": int(parts[2]),
            "failed_attempts": int(parts[3]),
            "self_destruct": bool(int(parts[4])),
            "fingerprint": parts[5],
            "creation_time": float(parts[6].strip()),
            "salt_values": parts[7].strip(),  # 盐值字符串
            "data_start": header_end
        }
    
    def update_metadata(self, encrypted_data: bytes, metadata: dict) -> bytes:
        """
        更新加密数据中的元数据
        
        Args:
            encrypted_data: 加密后的数据
            metadata: 更新后的元数据
            
        Returns:
            更新后的加密数据
        """
        # 解析原始元数据
        original_metadata = self.parse_metadata(encrypted_data)
        
        # 构建新的元数据头
        magic = metadata.get("magic", original_metadata["magic"])
        original_extension = metadata.get("original_extension", original_metadata["original_extension"]).ljust(10, " ")
        max_attempts = str(metadata.get("max_attempts", original_metadata["max_attempts"])).zfill(3)
        failed_attempts = str(metadata.get("failed_attempts", original_metadata["failed_attempts"])).zfill(3)
        self_destruct = str(int(metadata.get("self_destruct", original_metadata["self_destruct"])))
        fingerprint = metadata.get("fingerprint", original_metadata["fingerprint"]).ljust(32, " ")[:32]  # 固定32字节
        creation_time = f"{metadata.get('creation_time', original_metadata['creation_time']):.6f}".ljust(20, " ")  # 固定20字节
        salt_values = metadata.get("salt_values", original_metadata["salt_values"]).ljust(200, " ")  # 固定200字节，支持更多加密层级
        
        # 构建新的元数据头
        new_header = f"{magic}|{original_extension}|{max_attempts}|{failed_attempts}|{self_destruct}|{fingerprint}|{creation_time}|{salt_values}|"
        
        # 获取原始加密数据
        original_data = encrypted_data[original_metadata["data_start"]:]
        
        # 返回更新后的加密数据
        return new_header.encode() + original_data
    
    def irreversible_self_destruct(self, file_path: str = "") -> bool:
        """
        执行不可逆的自毁操作
        
        Args:
            file_path: 文件路径
            
        Returns:
            是否成功自毁
        """
        try:
            if file_path and os.path.exists(file_path):
                # 首先覆盖文件内容，使用随机数据填充
                file_size = os.path.getsize(file_path)
                with open(file_path, 'wb') as f:
                    # 分块写入随机数据，确保数据被覆盖
                    chunk_size = 1024 * 1024  # 1MB块
                    total_written = 0
                    while total_written < file_size:
                        write_size = min(chunk_size, file_size - total_written)
                        f.write(os.urandom(write_size))
                        total_written += write_size
                    f.flush()
                    os.fsync(f.fileno())
                
                # 然后删除文件
                os.remove(file_path)
                return True
            return False
        except Exception:
            return False
    
    def nested_decrypt(self, encrypted_data: bytes, keys: list, machine_id: str = "", file_path: str = "") -> tuple[bytes, dict, bool]:
        """
        多层嵌套解密
        
        Args:
            encrypted_data: 加密后的数据
            keys: 密钥列表，从外层到内层（与加密顺序相同）
            machine_id: 机器唯一标识符
            file_path: 文件路径，用于防复制
            
        Returns:
            (解密后的数据, 元数据, 是否触发自毁)
        """
        # 解析元数据
        metadata = self.parse_metadata(encrypted_data)
        
        # 检查是否已触发自毁
        if metadata["self_destruct"]:
            return b"", metadata, True
        
        # 提取加密数据部分
        data_part = encrypted_data[metadata["data_start"]:]
        
        # 尝试解密
        try:
            # 首先进行密钥解密
            decrypted_data = data_part
            
            # 解析盐值
            salt_values_hex = metadata["salt_values"]
            salt_values = []
            if salt_values_hex.strip():
                # 将盐值从十六进制字符串转换为字节数组
                salt_values = [bytes.fromhex(salt_hex) for salt_hex in salt_values_hex.split(",") if salt_hex.strip()]
            
            # 确保盐值数量与密钥数量匹配
            if len(salt_values) != len(keys):
                print(f"盐值数量({len(salt_values)})与密钥数量({len(keys)})不匹配")
                # 解密顺序与加密顺序相反
                for i, password in enumerate(reversed(keys)):
                    # 生成新的盐值，不使用保存的盐值
                    key, _ = self.generate_key(password)
                    decrypted_data = self.decrypt(decrypted_data, key)
            else:
                # 解密顺序与加密顺序相反，使用对应的盐值
                # 加密时顺序：keys[0] -> keys[1] -> keys[2]，每层使用salt_values[0], salt_values[1], salt_values[2]
                # 解密时顺序：keys[2] -> keys[1] -> keys[0]，每层使用salt_values[2], salt_values[1], salt_values[0]
                for i, password in enumerate(reversed(keys)):
                    # 获取对应的盐值，解密顺序与加密顺序相反
                    salt_index = len(keys) - 1 - i
                    salt = salt_values[salt_index]
                    key, _ = self.generate_key(password, salt)
                    decrypted_data = self.decrypt(decrypted_data, key)
            
            # 检查解密后数据是否为空
            if not decrypted_data:
                # 解密失败，增加失败尝试次数
                new_failed_attempts = metadata["failed_attempts"] + 1
                metadata["failed_attempts"] = new_failed_attempts
                
                # 检查是否达到最大尝试次数
                if new_failed_attempts >= metadata["max_attempts"]:
                    # 触发自毁
                    metadata["self_destruct"] = True
                    return b"", metadata, True
                
                return b"", metadata, False
            
            # 获取文件创建时间
            creation_time = metadata["creation_time"]
            
            # 生成当前文件的指纹，使用原始创建时间和当前文件路径
            current_fingerprint = self.generate_file_fingerprint(decrypted_data, creation_time, machine_id, file_path)
            
            # 截取前32字节进行比较
            current_fingerprint_short = current_fingerprint[:32]
            
            # 验证指纹是否匹配
            if current_fingerprint_short != metadata["fingerprint"]:
                # 指纹不匹配，触发自毁
                metadata["self_destruct"] = True
                return b"", metadata, True
            
            return decrypted_data, metadata, False
        except Exception as e:
            # 解密失败，增加失败尝试次数
            new_failed_attempts = metadata["failed_attempts"] + 1
            metadata["failed_attempts"] = new_failed_attempts
            
            # 检查是否达到最大尝试次数
            if new_failed_attempts >= metadata["max_attempts"]:
                # 触发自毁
                metadata["self_destruct"] = True
                return b"", metadata, True
            
            return b"", metadata, False



