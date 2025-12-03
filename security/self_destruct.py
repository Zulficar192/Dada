#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自毁机制模块
"""

import os
import shutil
import hashlib
from typing import List


class SelfDestructor:
    """自毁机制类"""
    
    def __init__(self, max_attempts: int = 3):
        self.max_attempts = max_attempts
        self.failed_attempts = 0
        self.files_to_destroy: List[str] = []
    
    def add_file_to_destroy(self, file_path: str) -> None:
        """
        添加要销毁的文件
        
        Args:
            file_path: 文件路径
        """
        if os.path.exists(file_path) and file_path not in self.files_to_destroy:
            self.files_to_destroy.append(file_path)
    
    def remove_file_to_destroy(self, file_path: str) -> None:
        """
        移除要销毁的文件
        
        Args:
            file_path: 文件路径
        """
        if file_path in self.files_to_destroy:
            self.files_to_destroy.remove(file_path)
    
    def record_failed_attempt(self) -> bool:
        """
        记录失败尝试
        
        Returns:
            是否激活自毁机制
        """
        self.failed_attempts += 1
        return self.failed_attempts >= self.max_attempts
    
    def reset_attempts(self) -> None:
        """
        重置失败尝试计数
        """
        self.failed_attempts = 0
    
    def destroy_files(self) -> None:
        """
        销毁所有标记的文件
        """
        for file_path in self.files_to_destroy:
            self._destroy_single_file(file_path)
        # 清空列表
        self.files_to_destroy.clear()
    
    def _destroy_single_file(self, file_path: str) -> None:
        """
        销毁单个文件
        
        Args:
            file_path: 文件路径
        """
        try:
            if not os.path.exists(file_path):
                return
            
            # 第一步：覆盖文件内容
            file_size = os.path.getsize(file_path)
            with open(file_path, "wb") as f:
                # 写入随机数据覆盖文件
                f.write(os.urandom(file_size))
            
            # 第二步：重命名文件多次，增加恢复难度
            for i in range(5):
                new_path = f"{file_path}.{i}.tmp"
                os.rename(file_path, new_path)
                file_path = new_path
            
            # 第三步：删除最终文件
            os.remove(file_path)
            
            # 如果是目录，递归销毁
            if os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            # 忽略销毁过程中的错误，继续销毁其他文件
            pass
    
    def destroy_encrypted_data(self, encrypted_data: bytes) -> bytes:
        """
        销毁加密数据
        
        Args:
            encrypted_data: 加密数据
            
        Returns:
            销毁后的数据（空字节）
        """
        return b""  # 返回空字节，表示数据已销毁
    
    def is_destruct_sequence(self, password: str) -> bool:
        """
        检查是否为自毁序列
        
        Args:
            password: 输入的密码
            
        Returns:
            是否为自毁序列
        """
        # 简单实现：特定密码序列触发自毁
        destruct_sequences = ["destroy", "自毁", "selfdestruct", "@#$DESTROY@#$"]
        return password.lower() in destruct_sequences
