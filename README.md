# Kernel Mode Memory Driver

A Windows kernel mode driver for process memory operations with usermode communication interface. This driver provides controlled access to process memory through IOCTL operations.

## Features

- **Process Attachment**: Validate and attach to target processes
- **Memory Reading**: Read process memory with safety checks
- **Module Resolution**: Get base addresses of loaded modules
- **Process Discovery**: Find process IDs by name
- **Batch Operations**: Perform multiple memory reads efficiently
- **Security Validation**: Address bounds checking and access violation handling

## Driver Architecture

### Device Information
- **Device Name**: `\Device\laithdriver`
- **Symbolic Link**: `\DosDevices\laithdriver`
- **Communication Method**: Buffered I/O via IOCTL

### Supported IOCTL Codes

| Operation | Code | Description |
|-----------|------|-------------|
| `ATTACH` | `0x800` | Validate process access |
| `READ` | `0x801` | Read process memory |
| `GET_MODULE` | `0x802` | Get module base address |
| `GET_PID` | `0x803` | Find process ID by name |
| `BATCH_READ` | `0x804` | Perform multiple reads |

## Security Features

- **Address Validation**: Ensures target addresses are within valid user space ranges
- **Size Limits**: Prevents excessive memory operations
- **Overflow Protection**: Checks for integer overflow in address calculations
- **Exception Handling**: Uses SEH to catch access violations
- **Process Reference Management**: Proper cleanup of process references

## Usage Examples

### Basic Process Attachment
```cpp
// Connect to driver
HANDLE driver = CreateFile(L"\\\\.\\laithdriver", 
    GENERIC_READ | GENERIC_WRITE, 0, nullptr, 
    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

// Attach to process
struct {
    HANDLE process_id;
    PVOID target;
    PVOID buffer;
    SIZE_T size;
} request = { ULongToHandle(pid), nullptr, nullptr, 0 };

DeviceIoControl(driver, IOCTL_ATTACH, &request, sizeof(request), 
    &request, sizeof(request), nullptr, nullptr);
```

### Memory Reading
```cpp
// Read memory from attached process
DWORD64 value;
struct {
    HANDLE process_id;
    PVOID target;
    PVOID buffer;
    SIZE_T size;
} readRequest = { 
    ULongToHandle(pid), 
    (PVOID)address, 
    &value, 
    sizeof(value) 
};

BOOL success = DeviceIoControl(driver, IOCTL_READ, 
    &readRequest, sizeof(readRequest), 
    &readRequest, sizeof(readRequest), 
    nullptr, nullptr);
```

### Module Base Resolution
```cpp
// Get module base address
typedef struct {
    UINT32 pid;
    UINT64 baseAddress;
    WCHAR moduleName[1024];
} MODULE_PACK;

MODULE_PACK modulePack = { 0 };
modulePack.pid = targetPid;
wcscpy_s(modulePack.moduleName, L"ntdll.dll");

DeviceIoControl(driver, IOCTL_GET_MODULE_BASE, 
    &modulePack, sizeof(modulePack), 
    &modulePack, sizeof(modulePack), 
    nullptr, nullptr);

DWORD64 moduleBase = modulePack.baseAddress;
```

### Batch Memory Operations
```cpp
// Efficient multiple memory reads
struct BatchReadRequest {
    DWORD64 address;
    SIZE_T size;
    SIZE_T offset_in_buffer;
};

struct BatchReadHeader {
    HANDLE process_id;
    UINT32 num_requests;
    SIZE_T total_buffer_size;
};

// Construct batch request with header + requests + output buffer
std::vector<BYTE> batchBuffer(sizeof(BatchReadHeader) + 
    (requestCount * sizeof(BatchReadRequest)) + outputSize);

BatchReadHeader* header = (BatchReadHeader*)batchBuffer.data();
header->process_id = ULongToHandle(pid);
header->num_requests = requestCount;
header->total_buffer_size = outputSize;

// Add individual requests...
// Perform batch operation
DeviceIoControl(driver, IOCTL_BATCH_READ, batchBuffer.data(), 
    batchBuffer.size(), batchBuffer.data(), batchBuffer.size(), 
    nullptr, nullptr);
```

## Safety Considerations

### Address Validation
- Addresses must be within user space (`< 0x7FFFFFFFFFFF`)
- Minimum address threshold (`> 0x10000`)
- Overflow detection in address arithmetic

### Size Limitations
- Single read: Maximum 4KB (`0x1000` bytes)
- Batch read: Maximum 8KB (`0x2000` bytes) per request
- Batch count: Maximum 1M requests

### Error Handling
All operations return appropriate NTSTATUS codes:
- `STATUS_SUCCESS`: Operation completed successfully
- `STATUS_INVALID_PARAMETER`: Invalid input parameters
- `STATUS_ACCESS_VIOLATION`: Memory access violation
- `STATUS_NOT_FOUND`: Process/module not found

## Driver Loading

This driver is designed to be loaded using manual mapping techniques. The entry point `DriverEntry()` creates the driver object and establishes the device interface.

**Note**: This driver requires appropriate privileges and should only be used in authorized testing environments.

## Development Notes

- Built for Windows kernel development
- Requires Windows Driver Kit (WDK)
- Uses standard kernel APIs: `MmCopyVirtualMemory`, `PsLookupProcessByProcessId`
- Implements proper resource cleanup and reference counting

## Legal Notice

This software is provided under the MIT License for educational and research purposes. Users are responsible for ensuring compliance with applicable laws and regulations. Unauthorized use of this software for malicious purposes is strictly prohibited.

## License

MIT License

Copyright (c) 2024

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

**Disclaimer**: This driver is intended for educational and authorized security research purposes only. Misuse of this software may violate local laws and regulations.
