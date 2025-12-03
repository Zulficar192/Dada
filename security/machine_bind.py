#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
机器绑定模块
"""

import platform
import hashlib
import subprocess
import sys


class MachineBinder:
    """机器绑定类"""
    
    def __init__(self):
        self.machine_id = self.get_machine_id()
    
    def get_machine_id(self) -> str:
        """
        获取机器唯一标识
        
        Returns:
            机器唯一标识字符串
        """
        if platform.system() == "Windows":
            return self._get_windows_machine_id()
        elif platform.system() == "Linux":
            return self._get_linux_machine_id()
        elif platform.system() == "Darwin":
            return self._get_macos_machine_id()
        else:
            # 其他系统，使用平台信息生成唯一标识
            return self._get_generic_machine_id()
    
    def _get_windows_machine_id(self) -> str:
        """
        获取Windows机器唯一标识
        
        Returns:
            机器唯一标识字符串
        """
        try:
            # 使用WMIC获取主板序列号
            result = subprocess.check_output(["wmic", "baseboard", "get", "serialnumber"], 
                                           universal_newlines=True)
            serial = result.strip().split("\n")[1].strip()
            if serial and serial != "To be filled by O.E.M.":
                return hashlib.sha256(serial.encode()).hexdigest()
            
            # 如果主板序列号不可用，使用硬盘序列号
            result = subprocess.check_output(["wmic", "diskdrive", "get", "serialnumber"], 
                                           universal_newlines=True)
            serial = result.strip().split("\n")[1].strip()
            if serial:
                return hashlib.sha256(serial.encode()).hexdigest()
            
            # 如果都不可用，使用CPU ID
            result = subprocess.check_output(["wmic", "cpu", "get", "processorid"], 
                                           universal_newlines=True)
            serial = result.strip().split("\n")[1].strip()
            return hashlib.sha256(serial.encode()).hexdigest()
        except Exception:
            # 异常情况下使用通用方法
            return self._get_generic_machine_id()
    
    def _get_linux_machine_id(self) -> str:
        """
        获取Linux机器唯一标识
        
        Returns:
            机器唯一标识字符串
        """
        try:
            # 尝试读取machine-id文件
            with open("/etc/machine-id", "r") as f:
                machine_id = f.read().strip()
                if machine_id:
                    return hashlib.sha256(machine_id.encode()).hexdigest()
            
            # 尝试读取D-Bus machine-id
            with open("/var/lib/dbus/machine-id", "r") as f:
                machine_id = f.read().strip()
                return hashlib.sha256(machine_id.encode()).hexdigest()
        except Exception:
            return self._get_generic_machine_id()
    
    def _get_macos_machine_id(self) -> str:
        """
        获取macOS机器唯一标识
        
        Returns:
            机器唯一标识字符串
        """
        try:
            # 使用ioreg获取硬件UUID
            result = subprocess.check_output(["ioreg", "-d2", "-c", "IOPlatformExpertDevice"], 
                                           universal_newlines=True)
            for line in result.split("\n"):
                if "IOPlatformUUID" in line:
                    uuid = line.split("=\s*")[1].strip().strip('"')
                    return hashlib.sha256(uuid.encode()).hexdigest()
            return self._get_generic_machine_id()
        except Exception:
            return self._get_generic_machine_id()
    
    def _get_generic_machine_id(self) -> str:
        """
        通用机器唯一标识生成方法
        
        Returns:
            机器唯一标识字符串
        """
        # 使用平台信息、CPU架构和内存信息生成唯一标识
        platform_info = f"{platform.system()}-{platform.architecture()[0]}-{platform.machine()}"
        return hashlib.sha256(platform_info.encode()).hexdigest()
    
    def is_authorized_machine(self, encrypted_machine_id: str) -> bool:
        """
        检查当前机器是否为授权机器
        
        Args:
            encrypted_machine_id: 加密的机器ID
            
        Returns:
            是否为授权机器
        """
        return self.machine_id == encrypted_machine_id
    
    def bind_to_machine(self, data: bytes) -> bytes:
        """
        将数据绑定到当前机器
        
        Args:
            data: 要绑定的数据
            
        Returns:
            绑定后的数据
        """
        # 简单实现：将机器ID作为前缀添加到数据中
        return self.machine_id.encode() + b"|" + data
    
    def unbind_from_machine(self, bound_data: bytes) -> bytes:
        """
        从数据中提取原始数据（移除机器绑定）
        
        Args:
            bound_data: 绑定了机器ID的数据
            
        Returns:
            原始数据
        """
        # 分割机器ID和原始数据
        parts = bound_data.split(b"|", 1)
        if len(parts) == 2:
            return parts[1]
        return bound_data
