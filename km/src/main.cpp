
#include "helpers.h"


namespace driver {
    namespace codes {
        constexpr ULONG attach =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG read =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG get_module =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG get_pid =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

        constexpr ULONG batch_read =
            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
    }

    NTSTATUS create(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    NTSTATUS close(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    NTSTATUS device_control(PDEVICE_OBJECT device_object, PIRP irp) {
        UNREFERENCED_PARAMETER(device_object);

        debug_print("Device control called\n");

        NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;

        PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);
        if (!stack_irp || !irp->AssociatedIrp.SystemBuffer) {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }

        switch (stack_irp->Parameters.DeviceIoControl.IoControlCode) {
        case codes::attach:
        {
            // Just validate the PID exists, don't store reference
            Request* request = (Request*)irp->AssociatedIrp.SystemBuffer;
            PEPROCESS temp_process = nullptr;
            status = PsLookupProcessByProcessId(request->process_id, &temp_process);

            if (NT_SUCCESS(status)) {
                ObDereferenceObject(temp_process); // Immediately release
                // Store just the PID for later use
                // You could add a global HANDLE stored_pid = request->process_id;
            }

            irp->IoStatus.Information = (NT_SUCCESS(status)) ? sizeof(Request) : 0;
        }
        break;

        case codes::read:
        {
            Request* request = (Request*)irp->AssociatedIrp.SystemBuffer;

            // Get fresh process reference each time
            PEPROCESS target_process = nullptr;
            status = PsLookupProcessByProcessId(request->process_id, &target_process);

            if (!NT_SUCCESS(status)) {
                irp->IoStatus.Information = 0;
                break;
            }

            // Validate parameters
            if (!request->target || !request->buffer || request->size == 0 || request->size > 0x1000) {
                ObDereferenceObject(target_process);
                status = STATUS_INVALID_PARAMETER;
                irp->IoStatus.Information = 0;
                break;
            }

            // ADD THIS: Validate target address is in user space and properly aligned
            if ((ULONG_PTR)request->target >= 0x7FFFFFFFFFFF ||
                (ULONG_PTR)request->target < 0x10000 ||
                ((ULONG_PTR)request->target + request->size) < (ULONG_PTR)request->target) {
                ObDereferenceObject(target_process);
                status = STATUS_ACCESS_VIOLATION;
                irp->IoStatus.Information = 0;
                break;
            }

            // ADD THIS: Use SEH to catch any access violations
            __try {
                SIZE_T return_size = 0;
                status = MmCopyVirtualMemory(target_process, request->target,
                    PsGetCurrentProcess(), request->buffer,
                    request->size, KernelMode, &return_size);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                status = STATUS_ACCESS_VIOLATION;
            }

            ObDereferenceObject(target_process);
            irp->IoStatus.Information = (NT_SUCCESS(status)) ? sizeof(Request) : 0;
        }
        break;

        case codes::get_pid:
        {
            P_PID_PACK pidPack = (P_PID_PACK)irp->AssociatedIrp.SystemBuffer;

            if (pidPack && pidPack->name[0] != 0) {
                HANDLE processId = GetPID(pidPack->name);
                pidPack->pid = HandleToULong(processId);

                status = (processId != NULL) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
                irp->IoStatus.Information = sizeof(PID_PACK);
            }
            else {
                status = STATUS_INVALID_PARAMETER;
                irp->IoStatus.Information = 0;
            }
        }
        break;

        case codes::get_module:
        {
            PMODULE_PACK_KM modulePack = (PMODULE_PACK_KM)irp->AssociatedIrp.SystemBuffer;

            if (modulePack && modulePack->moduleName[0] != 0 && modulePack->pid != 0) {
                // Convert wide char to ANSI
                char ansiModuleName[1024] = { 0 };
                status = WideCharToAnsi(modulePack->moduleName, ansiModuleName, sizeof(ansiModuleName));

                if (NT_SUCCESS(status)) {
                    HANDLE processId = ULongToHandle(modulePack->pid);

                    // Get process module base address
                    PVOID baseAddr = GetProcessModuleBase(processId, ansiModuleName);

                    modulePack->baseAddress = (UINT64)baseAddr;
                    status = (baseAddr != nullptr) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
                    irp->IoStatus.Information = sizeof(MODULE_PACK_KM);
                }
                else {
                    irp->IoStatus.Information = 0;
                }
            }
            else {
                status = STATUS_INVALID_PARAMETER;
                irp->IoStatus.Information = 0;
            }
        }
        break;

        case codes::batch_read:
        {
            PBatchReadHeader header = (PBatchReadHeader)irp->AssociatedIrp.SystemBuffer;

            // Validate input parameters
            if (!header || header->num_requests == 0 || header->num_requests > 0x100000) {
                status = STATUS_INVALID_PARAMETER;
                irp->IoStatus.Information = 0;
                break;
            }

            // Validate buffer size
            SIZE_T expected_min_size = sizeof(BatchReadHeader) +
                (header->num_requests * sizeof(BatchReadRequest));

            if (stack_irp->Parameters.DeviceIoControl.InputBufferLength < expected_min_size) {
                status = STATUS_BUFFER_TOO_SMALL;
                irp->IoStatus.Information = 0;
                break;
            }

            // Get target process
            PEPROCESS target_process = nullptr;
            status = PsLookupProcessByProcessId(header->process_id, &target_process);

            if (!NT_SUCCESS(status)) {
                irp->IoStatus.Information = 0;
                break;
            }

            // Get pointer to request array (right after header)
            PBatchReadRequest requests = (PBatchReadRequest)(header + 1);

            // Get pointer to output buffer (after request array)
            BYTE* output_buffer = (BYTE*)requests + (header->num_requests * sizeof(BatchReadRequest));

            UINT32 successful_reads = 0;

            __try {
                // Process each read request
                for (UINT32 i = 0; i < header->num_requests; ++i) {
                    PBatchReadRequest req = &requests[i];

                    // Validate individual request parameters
                    if (!req->address ||
                        req->size == 0 ||
                        req->size > 0x2000 ||  // Increased limit for batch operations
                        (ULONG_PTR)req->address >= 0x7FFFFFFFFFFF ||
                        (ULONG_PTR)req->address < 0x10000) {

                        // Zero out the output buffer for invalid requests
                        if (req->offset_in_buffer + req->size <= header->total_buffer_size) {
                            RtlZeroMemory(output_buffer + req->offset_in_buffer, req->size);
                        }
                        continue;
                    }

                    // Check for integer overflow in address calculation
                    if ((ULONG_PTR)req->address + req->size < (ULONG_PTR)req->address) {
                        if (req->offset_in_buffer + req->size <= header->total_buffer_size) {
                            RtlZeroMemory(output_buffer + req->offset_in_buffer, req->size);
                        }
                        continue;
                    }

                    // Validate output buffer bounds
                    if (req->offset_in_buffer + req->size > header->total_buffer_size) {
                        continue;
                    }

                    // Perform the memory read
                    SIZE_T bytes_read = 0;
                    NTSTATUS read_status = MmCopyVirtualMemory(
                        target_process,
                        (PVOID)req->address,
                        PsGetCurrentProcess(),
                        output_buffer + req->offset_in_buffer,
                        req->size,
                        KernelMode,
                        &bytes_read
                    );

                    if (NT_SUCCESS(read_status) && bytes_read == req->size) {
                        successful_reads++;
                    }
                    else {
                        // Zero out failed reads to provide consistent behavior
                        RtlZeroMemory(output_buffer + req->offset_in_buffer, req->size);
                    }
                }

                // Set success if at least some reads succeeded
                status = (successful_reads > 0) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;

            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                debug_print("Exception in batch read operation\n");
                status = STATUS_ACCESS_VIOLATION;
            }

            // Clean up process reference
            ObDereferenceObject(target_process);

            // Set the number of bytes to return (entire buffer)
            irp->IoStatus.Information = NT_SUCCESS(status) ?
                stack_irp->Parameters.DeviceIoControl.InputBufferLength : 0;
        }
        break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            irp->IoStatus.Information = 0;
            break;
        }

        irp->IoStatus.Status = status;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return status;
    }
}

// real entry point
NTSTATUS driver_main(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path) {
	UNREFERENCED_PARAMETER(registry_path);

	UNICODE_STRING device_name = {};
	RtlInitUnicodeString(&device_name, L"\\Device\\laithdriver"); // Device

	// create driver device obj
	PDEVICE_OBJECT device_object = nullptr;
	NTSTATUS status = IoCreateDevice(driver_object, 0, &device_name, FILE_DEVICE_UNKNOWN,
		FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);

	if (status != STATUS_SUCCESS) {
		debug_print("Failed to create driver device.\n");
		return status;
	}

	debug_print("Driver device successfully created.\n");

	UNICODE_STRING symbolic_link = {};
	RtlInitUnicodeString(&symbolic_link, L"\\DosDevices\\laithdriver"); // DosDevices

	status = IoCreateSymbolicLink(&symbolic_link, &device_name);
	if (status != STATUS_SUCCESS) {
		debug_print("Failed to establish symbolic link.\n");
		return status;
	}

	debug_print("Driver symbolic link successfully establish.\n");

	// flag for sending small amounts of data between um/km
	SetFlag(device_object->Flags, DO_BUFFERED_IO);

	driver_object->MajorFunction[IRP_MJ_CREATE] = driver::create;
	driver_object->MajorFunction[IRP_MJ_CLOSE] = driver::close;
	driver_object->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver::device_control;

	// device has been initialized final step
	ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

	debug_print("Driver initialized successfully.\n");

	return status;
}

// kdmapper calls this entry point 
NTSTATUS DriverEntry() {
	debug_print("Hello, World from the kernel!\n");

	UNICODE_STRING driver_name = {};
	RtlInitUnicodeString(&driver_name, L"\\Driver\\laithdriver"); // Driver

	return IoCreateDriver(&driver_name, &driver_main);
}
