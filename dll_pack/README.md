# PE Packer - DLL 打包器

一个 Windows PE 打包器，将验证 DLL 捆绑到可执行程序中。

## 功能

- 将 DLL 作为 overlay 追加到目标程序
- 修改 PE 入口点到 loader stub
- x86/x64 统一行为：`stub -> AppID 校验 -> 原始入口点`
- 校验失败时终止执行路径

## 构建

需要 Windows 环境（MSVC 或 MinGW-w64）。

```bash
cd dll_pack
build.bat
```

## 使用方法

```bash
packer.exe -in <input.exe> -out <output.exe> -appid <id> [-dll <validator.dll>] [-loader-mode <full|compat>]
```

参数：
- `-in <file>` - 输入程序
- `-out <file>` - 输出程序
- `-appid <num>` - 应用程序 ID（有效范围 100-1000）
- `-dll <file>` - 验证 DLL（默认：validator.dll）
- `-loader-mode <full|compat>` - 运行时 loader 策略（默认 `full`）
  - `full`：AppID 范围校验 + 跳转原始入口点（当前默认）
  - `compat`：只跳转原始入口点（兼容回退模式）

## 当前真实生效路径

- `packer`：只负责 PE 改写与 overlay 附加
- `loader`：只负责运行时校验与跳转
- 默认产物运行链路：`stub(full) -> validate(AppID range) -> 原始入口点`
- 回退产物运行链路：`stub(compat) -> 原始入口点`

说明：`完整 Validate(DLL)` 相关代码保留在 `src/loader/` 下作为后续目标实现，不是当前默认产物路径；当前通过 `loader-mode` 保证“默认严格 + 可回退兼容”。

## 可量化目标与当前门槛

- 兼容性：x86/x64 打包命令一致；回退模式可用（`full/compat`）
- 稳定性：Windows CI 案例通过率目标 100%
- 结构一致性：导入表、重定位表、TLS 目录打包前后保持一致
- 安全基线：默认模式保留 AppID 策略校验；ASLR 按当前设计关闭，DEP 标志保持

上述指标在 CI 中由 `check_pe`、`check_aslr`、`check_pack_consistency` 共同验证。

## 目录结构

```text
dll_pack/
├── src/
│   ├── packer/
│   ├── loader/
│   │   ├── active_loader.h
│   │   └── archive/
│   └── validator/
├── build.bat
└── README.md
```

## Windows CI 测试

仓库包含 Windows 工作流：

- 文件：`.github/workflows/dll-pack-windows.yml`
- 内容：在 `windows-latest` 上执行
  1. `build.bat` 构建 `validator.dll` 和 `packer.exe`
  2. 构建 `test_program.exe`、`check_pe.exe`、`check_aslr.exe`、`check_pack_consistency.exe`
  3. 运行 `full` 和 `compat` 两种打包模式并校验结构一致性
  4. 运行最小破坏性用例（缺失 DLL、非法 AppID、损坏 PE）
  5. 失败时上传 Windows 构建产物用于定位

## 验证 DLL API

```c
BOOL WINAPI Validate(DWORD appid);
```

## 许可证

MIT License
