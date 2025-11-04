# 基于TEE模拟的动态信誉存储时间证明实验项目

本项目实现了一个基于可信执行环境(TEE)模拟的动态信誉存储时间证明系统。该系统通过模拟TEE环境，实现了数据存储、证明生成、验证以及信誉管理等功能，为后续迁移到真实的Intel SGX环境奠定基础。

## 项目结构
tee_sim_proof_project/          # 项目根目录
├── cmake/                      # CMake依赖配置
│   └── FindOpenSSL.cmake       # OpenSSL查找配置
├── src/
│   ├── tee_simulator/          # TEE模拟层（后期替换为SGX Enclave）
│   ├── core/                   # 核心业务层（方案核心逻辑）
│   │   ├── init/               # 初始化阶段模块
│   │   ├── proof_generator/    # 证明生成阶段模块
│   │   └── verifier/           # 验证阶段模块
│   ├── blockchain_sim/         # 区块链模拟层（合约逻辑）
│   └── utils/                  # 工具层（通用功能）
├── include/                    # 全局头文件（类型定义）
├── test/                       # 测试层
├── main.cpp                    # 主程序（完整实验流程）
├── CMakeLists.txt              # 项目编译配置
└