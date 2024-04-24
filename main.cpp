#include <ntifs.h>
#include "ntdef_k.h"
#pragma warning(disable:4996) 

static ULONG driverId = 1;

NTSTATUS CopyFile(PUNICODE_STRING _DstFileName,PUNICODE_STRING _SrcFileName)
{
    HANDLE hopenfile = NULL;
    NTSTATUS ntStatus = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES object = { 0 };
    IO_STATUS_BLOCK  iostatus = { 0 };
    //打开文件
    InitializeObjectAttributes(&object, _SrcFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    ntStatus = ZwOpenFile(&hopenfile, GENERIC_READ, &object, &iostatus, FILE_SHARE_READ| FILE_SHARE_WRITE, FILE_SYNCHRONOUS_IO_NONALERT);
    if (NT_SUCCESS(ntStatus))
    {
        FILE_STANDARD_INFORMATION fsi = { 0 };
        ntStatus = ZwQueryInformationFile(hopenfile, &iostatus, &fsi, sizeof(fsi), FileStandardInformation);
        if (NT_SUCCESS(ntStatus))
        {
            OBJECT_ATTRIBUTES objectAttributes = { 0 };
            IO_STATUS_BLOCK ios = { 0 };
            HANDLE hfile = NULL;

            //创建文件
            //即使存在该文件，也创建
            InitializeObjectAttributes(&objectAttributes, _DstFileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
            ntStatus = ZwCreateFile(&hfile, GENERIC_WRITE, &objectAttributes, &ios, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if (NT_SUCCESS(ntStatus))
            {
                char buffer[0x1000];
                for (int i = 0; i < fsi.EndOfFile.QuadPart / sizeof(buffer); i++)
                {
                    ntStatus = ZwReadFile(hopenfile, NULL, NULL, NULL, &iostatus, buffer, sizeof(buffer), NULL, NULL);
                    if (!NT_SUCCESS(ntStatus))
                        break;
                    ntStatus = ZwWriteFile(hfile, NULL, NULL, NULL, &ios, buffer, sizeof(buffer), NULL, NULL);
                    if (!NT_SUCCESS(ntStatus))
                        break;
                }
                if (NT_SUCCESS(ntStatus) && fsi.EndOfFile.QuadPart % sizeof(buffer) != 0)
                {
                    ntStatus = ZwReadFile(hopenfile, NULL, NULL, NULL, &iostatus, buffer, fsi.EndOfFile.QuadPart % 4096, NULL, NULL);
                    if (NT_SUCCESS(ntStatus))
                    {
                        ntStatus = ZwWriteFile(hfile, NULL, NULL, NULL, &ios, buffer, fsi.EndOfFile.QuadPart % 4096, NULL, NULL);
                    }
                }
                ZwClose(hfile);
            }
        }
    }
    return ntStatus;
}

VOID LoadImageCallBack(
    _In_opt_ PUNICODE_STRING FullImageName,
    _In_ HANDLE ProcessId,                // pid into which image is being mapped
    _In_ PIMAGE_INFO ImageInfo
)
{
    UNREFERENCED_PARAMETER(FullImageName);
    UNREFERENCED_PARAMETER(ImageInfo);
    if (ProcessId == 0)
    {
        ULONG Size = PAGE_SIZE;
        PVOID Buffer = ExAllocatePoolWithTag(PagedPool, Size, 'bif');
        NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, Buffer, Size, &Size);
        if (Status == STATUS_INFO_LENGTH_MISMATCH)
        {
            ExFreePoolWithTag(Buffer, 'bif');
            Buffer = ExAllocatePoolWithTag(PagedPool, Size, 'bif');
            Status = ZwQuerySystemInformation(SystemModuleInformation, Buffer, Size, &Size);
        }
        if (NT_SUCCESS(Status))
        {
            PRTL_PROCESS_MODULES pModules = (PRTL_PROCESS_MODULES)Buffer;
            for (ULONG i = 0; i < pModules->NumberOfModules; i++)
            {
                if (pModules->Modules[i].ImageBase == ImageInfo->ImageBase)
                {
                    UNICODE_STRING _DstFileName;
                    WCHAR _DstFileNameBuff[256] = { 0 };
                    swprintf_s(_DstFileNameBuff, sizeof(_DstFileNameBuff) / sizeof(_DstFileNameBuff[0]), L"\\??\\D:\\driver_%d.sys", driverId++);
                    RtlInitUnicodeString(&_DstFileName, _DstFileNameBuff);

                    ANSI_STRING _SrcFileNameA;
                    UNICODE_STRING _SrcFileName;
                    RtlInitAnsiString(&_SrcFileNameA, (char*)pModules->Modules[i].FullPathName);
                    RtlAnsiStringToUnicodeString(&_SrcFileName, &_SrcFileNameA, TRUE);
                    CopyFile(&_DstFileName, &_SrcFileName);
                    RtlFreeUnicodeString(&_SrcFileName);
                    break;
                }
            }
        }
        ExFreePoolWithTag(Buffer, 'bif');
    }
}


VOID DriverUnload(_In_ struct _DRIVER_OBJECT* DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    PsRemoveLoadImageNotifyRoutine(LoadImageCallBack);
}

extern "C" NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;

    PsSetLoadImageNotifyRoutine(LoadImageCallBack);
    return STATUS_SUCCESS;
}