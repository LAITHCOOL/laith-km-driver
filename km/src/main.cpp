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
        SIZE_T information = 0;

        PIO_STACK_LOCATION stack_irp = IoGetCurrentIrpStackLocation(irp);
        if (!stack_irp || !irp->AssociatedIrp.SystemBuffer) {
            irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            irp->IoStatus.Information = 0;
            IoCompleteRequest(irp, IO_NO_INCREMENT);
            return STATUS_INVALID_PARAMETER;
        }

        switch (stack_irp->Parameters.DeviceIoControl.IoControlCode) {
        case codes::attach:
            status = handle_attach(irp, &information);
            break;

        case codes::get_pid:
            status = handle_get_pid(irp, &information);
            break;

        case codes::get_module:
            status = handle_get_module(irp, &information);
            break;

        case codes::read:
            status = handle_read(irp, &information);
            break;

        case codes::batch_read:
            status = handle_batch_read(irp, stack_irp, &information);
            break;

        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            information = 0;
            break;
        }

        irp->IoStatus.Status = status;
        irp->IoStatus.Information = information;
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