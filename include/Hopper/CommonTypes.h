//
// Hopper Disassembler SDK
//
// (c) Cryptic Apps SARL. All Rights Reserved.
// https://www.hopperapp.com
//
// THIS CODE AND INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
// KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.
//

#ifndef _HOPPER_COMMONTYPES_H_
#define _HOPPER_COMMONTYPES_H_

#ifdef __OBJC__
    #import <Foundation/Foundation.h>
#endif

// Addresses

typedef uint64_t Address;
typedef struct {
    Address from;
    size_t  len;
} AddressRange;

#define BAD_ADDRESS     ((Address)-1)

// Colors

typedef uint32_t Color;
#define NO_COLOR 0

#if defined(__cplusplus)
# define HP_BEGIN_DECL_ENUM(BASE,TYPE) typedef enum : BASE
# define HP_END_DECL_ENUM(TYPE) TYPE
# define HP_BEGIN_DECL_OPTIONS(BASE,TYPE) \
    enum _k ## TYPE : BASE; \
    inline _k ## TYPE operator|(enum _k ## TYPE a, enum _k ## TYPE b) { return (enum _k ## TYPE) ((BASE)a | (BASE)b); } \
    inline _k ## TYPE operator|=(enum _k ## TYPE &a, enum _k ## TYPE b) { return (a = (enum _k ## TYPE) ((BASE)a | (BASE)b)); } \
    typedef enum _k ## TYPE: BASE
# define HP_END_DECL_OPTIONS(TYPE) TYPE ;
#else
# if defined(__OBJC__)
#  if defined(NS_ENUM)
#   define HP_BEGIN_DECL_ENUM(BASE,TYPE) typedef NS_ENUM(BASE,TYPE)
#   define HP_END_DECL_ENUM(TYPE)
#  else
#   define HP_BEGIN_DECL_ENUM(BASE,TYPE) typedef enum TYPE : BASE TYPE; enum TYPE : BASE
#   define HP_END_DECL_ENUM(TYPE)
#  endif
#  if defined(NS_OPTIONS)
#   define HP_BEGIN_DECL_OPTIONS(BASE,TYPE) typedef NS_OPTIONS(BASE,TYPE)
#   define HP_END_DECL_OPTIONS(TYPE)
#  else
#   define HP_BEGIN_DECL_OPTIONS(BASE,TYPE) typedef enum TYPE : BASE TYPE; enum TYPE : BASE
#   define HP_END_DECL_OPTIONS(TYPE)
#  endif
# else
#   define HP_BEGIN_DECL_ENUM(BASE,TYPE) typedef enum : BASE
#   define HP_END_DECL_ENUM(TYPE) TYPE
#   define HP_BEGIN_DECL_OPTIONS(BASE,TYPE) typedef enum : BASE
#   define HP_END_DECL_OPTIONS(TYPE) TYPE
#  endif
#endif

HP_BEGIN_DECL_ENUM(uint8_t, ByteType) {
    Type_Undefined,
    Type_Outside,

    Type_Next,      /// This memory block info is part of the previous bloc

    Type_Int8,
    Type_Int16,
    Type_Int32,
    Type_Int64,
    
    Type_ASCII,
    Type_Unicode,

    Type_ExternAddress = 0x3D,
    Type_ExternFunction = 0x3E,

    Type_Align = 0x3F,

    Type_Data = 0x40,      /// METATYPE : Only used for searching, no bytes have this type!
    
    Type_Code,
    Type_Procedure,

    Type_Structure,
}
HP_END_DECL_ENUM(ByteType);

HP_BEGIN_DECL_ENUM(uint8_t, CommentCreationReason) {
    CCReason_None,
    CCReason_Unknown,       // Unknown reason
    CCReason_User,          // Created by the user
    CCReason_Script,        // A Python script created the comment
    CCReason_Automatic,     // Automatic comment, like XREF comments, values found during the analysis...
    CCReason_Dynamic        // A dynamic comment. Its content depends on another MBI (the anchor).
}
HP_END_DECL_ENUM(CommentCreationReason);

HP_BEGIN_DECL_ENUM(uint8_t, NameCreationReason) {
    NCReason_None,
    NCReason_Unknown,       // Unknown reason
    NCReason_User,          // Created by the user
    NCReason_Script,        // A Python script created the name
    NCReason_Import,        // The name was read from the executable file
    NCReason_Metadata,      // The name was derived from metadata (like Objective-C)
    NCReason_Automatic      // An automatic temporary name (like sub_XXXXX)
}
HP_END_DECL_ENUM(NameCreationReason);

// Operand Format
#define FORMAT_TYPE_MASK  0x1F

HP_BEGIN_DECL_ENUM(NSUInteger, ArgFormat) {
    Format_Default,

    Format_Hexadecimal,
    Format_Decimal,
    Format_Octal,
    Format_Character,
    Format_StackVariable,
    Format_Offset,
    Format_Address,
    Format_Float,
    Format_Binary,

    Format_Structured,
    Format_Enum,

    Format_AddressDiff,

    Format_Negate = 0x20,
    Format_LeadingZeroes = 0x40,
    Format_Signed = 0x80
}
HP_END_DECL_ENUM(ArgFormat);

// Plugin

HP_BEGIN_DECL_ENUM(NSUInteger, HopperPluginType) {
    Plugin_CPU,
    Plugin_Loader,
    Plugin_Tool
}
HP_END_DECL_ENUM(HopperPluginType);

// CPU Definition

HP_BEGIN_DECL_ENUM(NSUInteger, CPUEndianess) {
    CPUEndianess_Little,
    CPUEndianess_Big
}
HP_END_DECL_ENUM(CPUEndianess);

// Register Class

#define MAX_REGISTER_CLASS  16

HP_BEGIN_DECL_ENUM(NSUInteger, RegClass) {
    RegClass_CPUState = 0,                // CPU State registers
    RegClass_PseudoRegisterSTACK = 1,     // Pseudo registers used to simulate the stack

    RegClass_GeneralPurposeRegister = 2,

    RegClass_FirstUserClass = 3,

    // x86
    RegClass_X86_FPU = RegClass_FirstUserClass,
    RegClass_X86_MMX,
    RegClass_X86_SSE,
    RegClass_X86_AVX,
    RegClass_X86_CR,
    RegClass_X86_DR,
    RegClass_X86_Special,
    RegClass_X86_MemMgmt,
    RegClass_X86_SEG,

    // ARM
    RegClass_ARM_VFP_Single = RegClass_FirstUserClass,
    RegClass_ARM_VFP_Double,
    RegClass_ARM_VFP_Quad,
    RegClass_ARM_Media,
    RegClass_ARM_Special,

    RegClass_LastUserClass = MAX_REGISTER_CLASS,

    RegClass_Variable = 100,
    RegClass_Argument = 101,
    RegClass_Temporaries = 102,
    RegClass_Special = 103
}
HP_END_DECL_ENUM(RegClass);

// File Loaders

HP_BEGIN_DECL_ENUM(NSUInteger, DFTPriority) {
    DFTP_VeryLow,
    DFTP_Low,
    DFTP_Normal,
    DFTP_High,
    DFTP_VeryHigh
}
HP_END_DECL_ENUM(DFTPriority);

HP_BEGIN_DECL_ENUM(NSUInteger, FileLoaderLoadingStatus) {
    DIS_OK,
    DIS_InvalidArguments,
    DIS_BadFormat,
    DIS_DebugMismatch,
    DIS_DebugUUIDMismatch,
    DIS_MissingProcessor,
    DIS_NotSupported
}
HP_END_DECL_ENUM(FileLoaderLoadingStatus);

HP_BEGIN_DECL_ENUM(NSUInteger, LOCKind) {
    LOC_Address,
    LOC_Checkbox,
    LOC_CPU,
    LOC_StringList,
    LOC_ComboxBox
}
HP_END_DECL_ENUM(LOCKind);

HP_BEGIN_DECL_ENUM(NSUInteger, DFTAddressWidth) {
    AW_16bits = 1,
    AW_32bits = 2,
    AW_64bits = 3
}
HP_END_DECL_ENUM(DFTAddressWidth);

HP_BEGIN_DECL_OPTIONS(NSUInteger, FileLoaderOptions) {
    FLS_None            = 0,
    FLS_ParseObjectiveC = (1 << 0),
    FLS_ParseSwift      = (1 << 1),
    FLS_ParseExceptions = (1 << 2)
}
HP_END_DECL_OPTIONS(FileLoaderOptions);

// Call Reference

HP_BEGIN_DECL_ENUM(NSUInteger, CallReferenceType) {
    Call_None,
    Call_Unknown,
    Call_Direct,            // A direct call, like JMP, CALL, etc.
    Call_ObjectiveC         // A call through objc_msgSend
}
HP_END_DECL_ENUM(CallReferenceType);

// Signatures

HP_BEGIN_DECL_ENUM(uint8_t, SignatureCreationReason) {
    SCReason_None,
    SCReason_Unknown,                   // Unknown reason
    SCReason_GuessedFromDecompilation,  // Signature built during the decompilation process
    SCReason_GuessedFromDataFlow,       // Signature built from the data flow analysis.
    SCReason_Called,                    // Signature built from a method call
    SCReason_Database,                  // A known signature, from the embedded database
    SCReason_Demangling,                // From demangling, or decoding a signature string
    SCReason_User                       // Defined by the user
}
HP_END_DECL_ENUM(SignatureCreationReason);

// Calling Conventions

HP_BEGIN_DECL_ENUM(NSUInteger, CallingConvention) {
    CallingConvention_default = 0,
    
    CallingConvention_cdecl = 1,
    CallingConvention_stdcall,
    CallingConvention_fastcall,
    CallingConvention_fastcall_borland,
    CallingConvention_thiscall,
    CallingConvention_watcom,
    CallingConvention_pascal,
    CallingConvention_clrcall,
    
    CallingConvention_AAPCS = 10,
    CallingConvention_AAPCS_VFP,
    
    CallingConvention_X86_64SysV = 20,
    CallingConvention_X86_64Win64,

    // Special calling convention used by the Objective-C runtime
    CallingConvention_AARCH64_arg0_x1 = 40,
    CallingConvention_AARCH64_arg0_x2,
    CallingConvention_AARCH64_arg0_x3,
    CallingConvention_AARCH64_arg0_x4,
    CallingConvention_AARCH64_arg0_x5,
    CallingConvention_AARCH64_arg0_x6,
    CallingConvention_AARCH64_arg0_x7,
    CallingConvention_AARCH64_arg0_x8,
    CallingConvention_AARCH64_arg0_x9,
    CallingConvention_AARCH64_arg0_x10,
    CallingConvention_AARCH64_arg0_x11,
    CallingConvention_AARCH64_arg0_x12,
    CallingConvention_AARCH64_arg0_x13,
    CallingConvention_AARCH64_arg0_x14,
    CallingConvention_AARCH64_arg0_x15,
    CallingConvention_AARCH64_arg0_x16,
    CallingConvention_AARCH64_arg0_x17,
    CallingConvention_AARCH64_arg0_x18,
    CallingConvention_AARCH64_arg0_x19,
    CallingConvention_AARCH64_arg0_x20,
    CallingConvention_AARCH64_arg0_x21,
    CallingConvention_AARCH64_arg0_x22,
    CallingConvention_AARCH64_arg0_x23,
    CallingConvention_AARCH64_arg0_x24,
    CallingConvention_AARCH64_arg0_x25,
    CallingConvention_AARCH64_arg0_x26,
    CallingConvention_AARCH64_arg0_x27,
    CallingConvention_AARCH64_arg0_x28
}
HP_END_DECL_ENUM(CallingConvention);

#endif
