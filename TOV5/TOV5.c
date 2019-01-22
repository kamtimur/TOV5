/*++
Copyright (c) 1999 - 2002  Microsoft Corporation
Module Name:
passThrough.c
Abstract:
This is the main module of the passThrough miniFilter driver.
This filter hooks all IO operations for both pre and post operation
callbacks.  The filter passes through the operations.
Environment:
Kernel mode
--*/

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <wdm.h>
#include <ntdef.h>

PDEVICE_OBJECT Global_DeviceObject = NULL;

void * malloc(size_t size)
{
	//return ExAllocatePool(NonPagedPool, size);
	return MmAllocateNonCachedMemory(size);
}

void free(void * p, size_t size)
{
	//ExFreePool(p);
	MmFreeNonCachedMemory(p, size);
}

#define LOG_PRINT(a, ...)\
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "%s:%d!    "a"\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)


VOID
PrintIrpInfo(
	PIRP Irp)
{
	PIO_STACK_LOCATION  irpSp;
	irpSp = IoGetCurrentIrpStackLocation(Irp);

	PAGED_CODE();

	LOG_PRINT("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
		Irp->AssociatedIrp.SystemBuffer);
	LOG_PRINT("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer);
	LOG_PRINT("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
		irpSp->Parameters.DeviceIoControl.Type3InputBuffer);
	LOG_PRINT("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.InputBufferLength);
	LOG_PRINT("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
		irpSp->Parameters.DeviceIoControl.OutputBufferLength);
	return;
}

VOID
PrintChars(
	_In_reads_(CountChars) PCHAR BufferAddress,
	_In_ size_t CountChars
)
{
	if (CountChars) {

		while (CountChars--) {

			if (*BufferAddress > 31
				&& *BufferAddress != 127) {

				LOG_PRINT("%02x:%c", *BufferAddress, *BufferAddress);

			}
			else {

				LOG_PRINT("%02x:.", *BufferAddress);

			}
			BufferAddress++;
		}
	}
	LOG_PRINT("\n");
	return;
}


#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")



/// ....

UNICODE_STRING g_ufullpaths;
CHAR g_buffer[1024] = { 0 };

/// ....

PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
PtInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

NTSTATUS
PtUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);


FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);


FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough2(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);



//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#pragma alloc_text(PAGE, PtInstanceSetup)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE, 0, NULL, PtPostOperationPassThrough2},
	{ IRP_MJ_DIRECTORY_CONTROL, 0, NULL,  PtPostOperationPassThrough },
	{ IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),	//  Size
	FLT_REGISTRATION_VERSION,   //  Version // Minifilter drivers must set this member to FLT_REGISTRATION_VERSION
	0,                          //  Flags
	NULL,                       //  Context
	Callbacks,                  //  Operation callbacks
	PtUnload,                   //  MiniFilterUnload
	PtInstanceSetup,            //  InstanceSetup
	NULL,						//  InstanceQueryTeardown
	NULL,						//  InstanceTeardownStart
	NULL,						//  InstanceTeardownComplete
	NULL,                       //  GenerateFileName
	NULL,                       //  GenerateDestinationFileName
	NULL                        //  NormalizeNameComponent
};



NTSTATUS
PtInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtInstanceSetup: Entered\n"));

	return STATUS_SUCCESS;
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	UNICODE_STRING deviceLink;
	RtlInitUnicodeString(&deviceLink, L"\\??\\Filter");
}



NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status;

	// Handlers configuration for IOCTL and Unload
	DriverObject->DriverUnload = Unload;


	UNREFERENCED_PARAMETER(RegistryPath);

	LOG_PRINT("PassThrough: Entered");
	status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
	FLT_ASSERT(NT_SUCCESS(status));
	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status))
		{
			FltUnregisterFilter(gFilterHandle);
		}
	}
	else
	{
		return status;
	}

	RtlCreateUnicodeString(&g_ufullpaths, L"\\Windows\\SysWOW64\\vaultcli.dll");
	KdPrint(g_ufullpaths);

	return status;
}

NTSTATUS
PtUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtUnload: Entered\n"));

	FltUnregisterFilter(gFilterHandle);

	return STATUS_SUCCESS;
}







// ....................................................

ULONG get_next_entry_offset(IN PVOID p_data, IN FILE_INFORMATION_CLASS file_info)
{
	if (p_data == NULL)
		return 0;
	switch (file_info)
	{
	case FileDirectoryInformation:
		return ((PFILE_DIRECTORY_INFORMATION)p_data)->NextEntryOffset;
	case FileFullDirectoryInformation:
		return ((PFILE_FULL_DIR_INFORMATION)p_data)->NextEntryOffset;
	case FileIdFullDirectoryInformation:
		return ((PFILE_ID_FULL_DIR_INFORMATION)p_data)->NextEntryOffset;
	case FileBothDirectoryInformation:
		return ((PFILE_BOTH_DIR_INFORMATION)p_data)->NextEntryOffset;
	case FileIdBothDirectoryInformation:
		return ((PFILE_ID_BOTH_DIR_INFORMATION)p_data)->NextEntryOffset;
	case FileNamesInformation:
		return ((PFILE_NAMES_INFORMATION)p_data)->NextEntryOffset;
	default:
		return 0;
	}
}

VOID set_next_fbuffer_offset(IN PVOID p_data, IN FILE_INFORMATION_CLASS file_info, IN ULONG offset)
{
	if (p_data == NULL)
		return;
	switch (file_info)
	{
	case FileDirectoryInformation:
		((PFILE_DIRECTORY_INFORMATION)p_data)->NextEntryOffset = offset;
		break;
	case FileFullDirectoryInformation:
		((PFILE_FULL_DIR_INFORMATION)p_data)->NextEntryOffset = offset;
		break;
	case FileIdFullDirectoryInformation:
		((PFILE_ID_FULL_DIR_INFORMATION)p_data)->NextEntryOffset = offset;
		break;
	case FileBothDirectoryInformation:
		((PFILE_BOTH_DIR_INFORMATION)p_data)->NextEntryOffset = offset;
		break;
	case FileIdBothDirectoryInformation:
		((PFILE_ID_BOTH_DIR_INFORMATION)p_data)->NextEntryOffset = offset;
		break;
	case FileNamesInformation:
		((PFILE_NAMES_INFORMATION)p_data)->NextEntryOffset = offset;
		break;
	}
}

PWSTR  get_entry_file_name(IN PVOID p_data, IN FILE_INFORMATION_CLASS file_info)
{
	if (p_data == NULL)
		return NULL;

	switch (file_info)
	{
	case FileDirectoryInformation:
		return ((PFILE_DIRECTORY_INFORMATION)p_data)->FileName;
	case FileFullDirectoryInformation:
		return ((PFILE_FULL_DIR_INFORMATION)p_data)->FileName;
	case FileIdFullDirectoryInformation:
		return ((PFILE_ID_FULL_DIR_INFORMATION)p_data)->FileName;
	case FileBothDirectoryInformation:
		return ((PFILE_BOTH_DIR_INFORMATION)p_data)->FileName;
	case FileIdBothDirectoryInformation:
		return ((PFILE_ID_BOTH_DIR_INFORMATION)p_data)->FileName;
	case FileNamesInformation:
		return ((PFILE_NAMES_INFORMATION)p_data)->FileName;
	default:
		return NULL;
	}
}

ULONG get_fbuffer_filename_length(IN PVOID p_data, IN FILE_INFORMATION_CLASS file_info)
{
	if (p_data == NULL)
		return 0;

	switch (file_info)
	{
	case FileDirectoryInformation:
		return ((PFILE_DIRECTORY_INFORMATION)p_data)->FileNameLength;
	case FileFullDirectoryInformation:
		return ((PFILE_FULL_DIR_INFORMATION)p_data)->FileNameLength;
	case FileIdFullDirectoryInformation:
		return ((PFILE_ID_FULL_DIR_INFORMATION)p_data)->FileNameLength;
	case FileBothDirectoryInformation:
		return ((PFILE_BOTH_DIR_INFORMATION)p_data)->FileNameLength;
	case FileIdBothDirectoryInformation:
		return ((PFILE_ID_BOTH_DIR_INFORMATION)p_data)->FileNameLength;
	case FileNamesInformation:
		return ((PFILE_NAMES_INFORMATION)p_data)->FileNameLength;
	default:
		return 0;
	}
}

BOOLEAN is_observing_file(IN PUNICODE_STRING file_name, IN PUNICODE_STRING folder_name)//, IN PPRE_2_POST_CONTEXT p2pCtx)
{
	UNICODE_STRING test;
	//RtlInitUnicodeString(&test, "r\x00""e\x00s\x00u\x00l\x00t\x00.\x00t\x00x\x00t\x00\x00\x00");
	// RtlInitUnicodeString(&test, "C\x00o\x00o\x00k\x00i\x00e\x00s\x00\x00\x00");
	RtlCreateUnicodeString(&test, L"Cookies");


	PCHAR concatenated_buffer = malloc(folder_name->Length + file_name->Length + 2 + 2);
	memcpy(concatenated_buffer, folder_name->Buffer, folder_name->Length);
	concatenated_buffer[folder_name->Length] = '\\';
	concatenated_buffer[folder_name->Length + 1] = 0;
	memcpy(concatenated_buffer + folder_name->Length + 2, file_name->Buffer, file_name->Length);
	//concatenated_buffer[folder_name->Length + file_name->Length + 2 - 8] = 0;
	//concatenated_buffer[folder_name->Length + file_name->Length + 2 + 1 - 8] = 0;
	UNICODE_STRING uString3;
	RtlInitUnicodeString(&uString3, concatenated_buffer);

	LOG_PRINT("[+] file_name: %wZ \\ %wZ \\ %d\n", folder_name, file_name, file_name->Length);
	// LOG_PRINT("[+] file_name: %wZ \\ %wZ \\ %d\n", folder_name, test, file_name->Length);

	if (RtlCompareUnicodeString(&test, file_name, FALSE) == RESULT_ZERO) {
		LOG_PRINT("[+] MATCHED FILENAME");
		LOG_PRINT("[+] detected needed file: %wZ\\%wZ", folder_name, file_name);
		LOG_PRINT("[+] uString3: %wZ \\ %d", &uString3, uString3.Length);
		LOG_PRINT("[+] g_ufullpaths: %wZ \\ %d\n", &g_ufullpaths, g_ufullpaths.Length);
		// PrintChars(g_ufullpaths.Buffer, g_ufullpaths.Length);
		// PrintChars(uString3.Buffer, uString3.Length);
		// return TRUE;
	}

	if (RtlCompareUnicodeString(&uString3, &g_ufullpaths, FALSE) == RESULT_ZERO)
	{
		// PrintChars(file_name->Buffer, file_name->Length);
		// PrintChars(test.Buffer, test.Length);
		LOG_PRINT("[+] MATCHED FULL PATH");
		LOG_PRINT("[+] detected needed file: %wZ\\%wZ", folder_name, file_name);
		LOG_PRINT("[+] detected needed file: %wZ \\ %d\n", &uString3, uString3.Length);
		return TRUE;
	}


	//for (int i = 0; i < G_UNAMES_SIZE; i++)
	//{
	//	if (file_name->Length == g_ufiles[i].Length &&
	//		folder_name->Length == g_ufolders[i].Length &&
	//		// p2pCtx->VolCtx->Name.Length == g_uvolume.Length &&
	//		RtlCompareUnicodeStrings(file_name->Buffer, g_ufiles[i].Length / 2, g_ufiles[i].Buffer, g_ufiles[i].Length / 2, TRUE) == 0 &&
	//		RtlCompareUnicodeStrings(folder_name->Buffer, g_ufolders[i].Length / 2, g_ufolders[i].Buffer, g_ufolders[i].Length / 2, TRUE) == 0)// &&
	//																																		   //RtlCompareUnicodeStrings(p2pCtx->VolCtx->Name.Buffer, g_uvolume.Length / 2, g_uvolume.Buffer, g_uvolume.Length / 2, TRUE) == 0)
	//	{
	//		LOG_PRINT("detected needed file: %wZ\\%wZ\n", folder_name, file_name);
	//		
	//		LOG_PRINT("!!! detected needed file: %wZ\\%d\n", &uString3, uString3.Length);
	//		LOG_PRINT("!!! detected needed file: %wZ\\%d\n", &(g_ufullpaths[0]), g_ufullpaths[0].Length);
	//		PrintChars(uString3.Buffer, uString3.Length);
	//		PrintChars(g_ufullpaths[0].Buffer, g_ufullpaths[0].Length);
	//		

	//		return TRUE;
	//	}
	//}
	return FALSE;
}


typedef NTSTATUS(*MYPROC)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

extern UCHAR *PsGetProcessImageFileName(IN PEPROCESS Process);

NTSTATUS
GetProcessImageName(
	PEPROCESS eProcess,
	PUNICODE_STRING* ProcessImageName
)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG returnedLength;
	HANDLE hProcess = NULL;

	PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

	if (eProcess == NULL)
	{
		return STATUS_INVALID_PARAMETER_1;
	}

	status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, KernelMode, &hProcess);
	if (!NT_SUCCESS(status))
	{
		LOG_PRINT("ObOpenObjectByPointer Failed: %08x\n", status);
		return status;
	}

	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");
	MYPROC ZwQueryInformationProcess = MmGetSystemRoutineAddress(&routineName);
	//LOG_PRINT("[+] ZwQueryInformationProcess: %d", ZwQueryInformationProcess);

	/* Query the actual size of the process path */
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		NULL, // buffer
		0,    // buffer size
		&returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		//LOG_PRINT("ZwQueryInformationProcess status = %x\n", status);
		goto cleanUp;
	}

	//*ProcessImageName = malloc(returnedLength);

	if (ProcessImageName == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanUp;
	}

	/* Retrieve the process path from the handle to the process */
	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		*ProcessImageName,
		returnedLength,
		&returnedLength);

	// if (!NT_SUCCESS(status)) free(*ProcessImageName, returnedLength);

cleanUp:

	ZwClose(hProcess);

	return status;
}

FLT_POSTOP_CALLBACK_STATUS PtPostOperationPassThrough2(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	if (!NT_SUCCESS(Data->IoStatus.Status) || FltObjects == 0 || FltObjects->FileObject == 0)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (RtlCompareUnicodeString(&g_ufullpaths, &FltObjects->FileObject->FileName, FALSE) == RESULT_ZERO) 
	{
		LOG_PRINT("[+] %wZ", &g_ufullpaths);

		PEPROCESS proc = IoThreadToProcess(Data->Thread);
		PUCHAR str;
		UNICODE_STRING exeName;
		LONG len;
		int ulen;
		str = PsGetProcessImageFileName(proc);
		if ((RtlCompareMemory(str, "explorer.exe", 10) == 10) || (RtlCompareMemory(str, "MsMpEng.exe", 10) == 10)) {
			LOG_PRINT("[+] allowed");
		}
		else {
			LOG_PRINT("[!] not allowed !!!");
		}

		NTSTATUS status = STATUS_UNSUCCESSFUL;
		char pni_[1024];
		PUNICODE_STRING pni = pni_;

		status = GetProcessImageName(IoThreadToProcess(Data->Thread), &pni);
		if (NT_SUCCESS(status))
		{
			LOG_PRINT("ProcessName = %ws\n", pni->Buffer);
		}
		else
		{
			LOG_PRINT("GetProcessImageName status = %x\n", status);
		}

	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	//UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);


	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		// Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY ||
		Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer == NULL ||
		//KeGetCurrentIrql() != PASSIVE_LEVEL ||
		FltObjects == 0 ||
		FltObjects->FileObject == 0)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	return FLT_POSTOP_FINISHED_PROCESSING;


	//LOG_PRINT("KeGetCurrentIrql: %d\n", KeGetCurrentIrql());

	// check parameters is correct
	if (!NT_SUCCESS(Data->IoStatus.Status) ||
		// Data->Iopb->MinorFunction != IRP_MN_QUERY_DIRECTORY ||
		Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer == NULL ||
		KeGetCurrentIrql() != PASSIVE_LEVEL ||
		FltObjects == 0 ||
		FltObjects->FileObject == 0)
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// check file info
	FILE_INFORMATION_CLASS fileInfo;
	fileInfo = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;

	PVOID cur_fbuffer = NULL;
	PVOID prev_fbuffer = NULL;
	ULONG next_offset = 0;
	UNICODE_STRING cur_filename;

	//get current directory buffer
	cur_fbuffer = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer;
	prev_fbuffer = 0;
	int f_id = 0;
	while (1)
	{
		// ...
		next_offset = get_next_entry_offset(cur_fbuffer, fileInfo);

		// filename
		cur_filename.Buffer = get_entry_file_name(cur_fbuffer, fileInfo);
		if (cur_filename.Buffer == NULL)
			break;
		cur_filename.Length = (cur_filename.MaximumLength = (USHORT)get_fbuffer_filename_length(cur_fbuffer, fileInfo));

		// ...
		if (is_observing_file(&cur_filename, &FltObjects->FileObject->FileName))
		{
			LOG_PRINT("[+] fileInfo: %d", fileInfo);
		}
		// check for end
		if (next_offset == 0)
			break;
		prev_fbuffer = cur_fbuffer;
		cur_fbuffer = (PVOID)((PCHAR)cur_fbuffer + next_offset);
	}
	return FLT_POSTOP_FINISHED_PROCESSING;
}
