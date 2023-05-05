//
//  AmigaLoader.m
//  AmigaLoader
//
//  Created by Vincent Bénony on 03/03/2014.
//  Copyright (c) 2014 Cryptic Apps. All rights reserved.
//

#import "AmigaLoader.h"

#ifdef LINUX
#include <endian.h>

int16_t OSReadBigInt16(const void *address, uintptr_t offset) {
    return be16toh(*(int16_t *) ((uintptr_t) address + offset));
}

int32_t OSReadBigInt32(const void *address, uintptr_t offset) {
    return be32toh(*(int32_t *) ((uintptr_t) address + offset));
}

void OSWriteBigInt32(void *address, uintptr_t offset, int32_t data) {
    *(int32_t *) ((uintptr_t) address + offset) = htobe32(data);
}

#endif

typedef NS_ENUM(uint32_t, HUNK_TYPE) {
    HUNK_UNIT = 999,
    HUNK_NAME = 1000,
    HUNK_CODE = 1001,
    HUNK_DATA = 1002,
    HUNK_BSS = 1003,
    HUNK_RELOC32 = 1004,
    HUNK_RELOC16 = 1005,
    HUNK_RELOC8 = 1006,
    HUNK_EXT = 1007,
    HUNK_SYMBOL = 1008,
    HUNK_DEBUG = 1009,
    HUNK_END = 1010,
    HUNK_HEADER = 1011,
    HUNK_OVERLAY = 1013,
    HUNK_BREAK = 1014,
    HUNK_DRELOC32 = 1015,
    HUNK_DRELOC16 = 1016,
    HUNK_DRELOC8 = 1017,
    HUNK_LIB = 1018,
    HUNK_INDEX = 1019,
    HUNK_RELOC32SHORT = 1020,
    HUNK_ABSRELOC16 = 1022,
    HUNK_PPC_CODE = 1257,
    HUNK_RELRELOC26 = 1260
};

@implementation AmigaLoader {
    NSObject<HPHopperServices> *_services;
}

+ (int)sdkVersion {
    return HOPPER_CURRENT_SDK_VERSION;
}

- (instancetype)initWithHopperServices:(NSObject<HPHopperServices> *)services {
    if (self = [super init]) {
        _services = services;
    }
    return self;
}

- (NSObject<HPHopperUUID> *)pluginUUID {
    return [_services UUIDWithString:@"b92d6db3-1a89-4c48-aff2-2d9e4343cb52"];
}

- (HopperPluginType)pluginType {
    return Plugin_Loader;
}

- (NSString *)pluginName {
    return @"Amiga Hunk";
}

- (NSString *)pluginDescription {
    return @"Amiga Hunk File Loader";
}

- (NSString *)pluginAuthor {
    return @"Vincent Bénony";
}

- (NSString *)pluginCopyright {
    return @"© Cryptic Apps SARL";
}

- (NSString *)pluginVersion {
    return @"0.0.1";
}

- (NSArray<NSString *> *)commandLineIdentifiers {
    return @[@"Amiga"];
}

- (CPUEndianess)endianess {
    return CPUEndianess_Big;
}

- (BOOL)canLoadDebugFiles {
    return NO;
}

// Returns an array of DetectedFileType objects.
- (NSArray *)detectedTypesForData:(const void *)fileBytes length:(size_t)fileLength ofFileNamed:(NSString *)filename atPath:(nullable NSString *)fileFullPath {
    if (fileLength < 4) return @[];

    if (OSReadBigInt32(fileBytes, 0) == HUNK_HEADER) {
        NSObject<HPDetectedFileType> *type = [_services detectedType];
        [type setFileDescription:@"Amiga Executable"];
        [type setAddressWidth:AW_32bits];
        [type setCpuFamily:@"motorola"];
        [type setCpuSubFamily:@"68000"];
        [type setShortDescriptionString:@"amiga_hunk"];
        return @[type];
    }

    return @[];
}

#define INCREMENT_PTR(P,V) P = (const void *) ((uintptr_t) P + (V))

- (FileLoaderLoadingStatus)loadData:(const void *)fileBytes length:(size_t)fileLength originalPath:(NSString *)fileFullPath usingDetectedFileType:(NSObject<HPDetectedFileType> *)fileType options:(FileLoaderOptions)options forFile:(NSObject<HPDisassembledFile> *)file usingCallback:(FileLoadingCallbackInfo)callback {
    const void *firstByte = (const void *)fileBytes;
    const void *lastByte = firstByte + fileLength;

    const void *bytes = firstByte;
    if (OSReadBigInt32(bytes, 0) != HUNK_HEADER) return DIS_BadFormat;
    INCREMENT_PTR(bytes, 4);

    // Read resident library names
    while (bytes < lastByte) {
        uint32_t stringLength = OSReadBigInt32(bytes, 0); INCREMENT_PTR(bytes, 4);
        if (stringLength == 0) break;
        INCREMENT_PTR(bytes, stringLength * 4);
    }

    uint32_t tableSize = OSReadBigInt32(bytes, 0); INCREMENT_PTR(bytes, 4);
    uint32_t firstHunk = OSReadBigInt32(bytes, 0); INCREMENT_PTR(bytes, 4);
    uint32_t lastHunk = OSReadBigInt32(bytes, 0); INCREMENT_PTR(bytes, 4);
    const void *sizes = bytes;
    INCREMENT_PTR(bytes, (lastHunk - firstHunk + 1) * 4);

    uint32_t *loadAddresses = (uint32_t *)alloca(sizeof(uint32_t) * tableSize);
    uint32_t firstAddress = 0x1000;
    uint32_t address = firstAddress;
    for (uint32_t i=0; i<tableSize; i++) {
        loadAddresses[i] = address;
        uint32_t size = OSReadBigInt32(sizes, i * 4);
        address += size * 4;
    }

    uint32_t currentHunkIndex = firstHunk;
    NSObject<HPSegment> *currentSegment = nil;

    while (bytes < lastByte) {
        float progress = (float) ((uintptr_t) bytes - (uintptr_t) firstByte) / (float) ((uintptr_t) lastByte - (uintptr_t) firstByte);
        callback(@"Loading Amiga File", progress);

        uint32_t hunk_id = OSReadBigInt32(bytes, 0); INCREMENT_PTR(bytes, 4);
        hunk_id &= 0x3FFFFFFF;

        if (hunk_id == HUNK_CODE || hunk_id == HUNK_DATA || hunk_id == HUNK_BSS) {
            uint32_t sizeInWords = OSReadBigInt32(bytes, 0); INCREMENT_PTR(bytes, 4);
            // BOOL inFastMem = ((size & 0x80000000) != 0);
            // BOOL inChipMem = ((size & 0x40000000) != 0);
            sizeInWords &= 0x3FFFFFFF;
            uint32_t sizeInBytes = sizeInWords * 4;

            if (sizeInWords) {
                uint32_t startAddress = loadAddresses[currentHunkIndex];
                uint32_t endAddress = startAddress + sizeInBytes;
                NSLog(@"Create section of %d bytes at [0x%x;0x%x[", sizeInWords * 4, startAddress, endAddress);
                NSObject<HPSegment> *segment = [file addSegmentAt:startAddress size:sizeInBytes];
                NSObject<HPSection> *section = [segment addSectionAt:startAddress size:sizeInBytes];
                currentSegment = segment;

                if (hunk_id == HUNK_CODE) {
                    segment.segmentName = @"CODE";
                    section.sectionName = @"code";
                    section.pureCodeSection = YES;
                }
                if (hunk_id == HUNK_DATA) {
                    segment.segmentName = @"DATA";
                    section.sectionName = @"data";
                }
                if (hunk_id == HUNK_BSS) {
                    segment.segmentName = @"BSS";
                    section.sectionName = @"bss";
                }

                NSString *comment = [NSString stringWithFormat:@"\n\nHunk %@\n\n", segment.segmentName];
                [file setComment:comment atVirtualAddress:startAddress reason:CCReason_Automatic];

                if (hunk_id != HUNK_BSS) {
                    NSData *segmentData = [NSData dataWithBytes:bytes length:sizeInBytes];
                    segment.mappedData = segmentData;
                    segment.fileOffset = bytes - fileBytes;
                    segment.fileLength = sizeInBytes;
                    section.fileOffset = segment.fileOffset;
                    section.fileLength = segment.fileLength;
                    INCREMENT_PTR(bytes, sizeInBytes);
                }
            }
        }
        else if (hunk_id == HUNK_RELOC32) {
            while (1) {
                uint32_t count = OSReadBigInt32(bytes, 0); INCREMENT_PTR(bytes, 4);
                if (count == 0) break;
                uint32_t target_hunk_number = OSReadBigInt32(bytes, 0); INCREMENT_PTR(bytes, 4);
                for (uint32_t i=0; i<count; i++) {
                    uint32_t offset = OSReadBigInt32(bytes, 0); INCREMENT_PTR(bytes, 4);
                    uint32_t original = OSReadBigInt32([currentSegment.mappedData bytes], offset);
                    original += loadAddresses[target_hunk_number];
                    OSWriteBigInt32((void *)[currentSegment.mappedData bytes], offset, original);
                }
            }
        }
        else if (hunk_id == HUNK_RELOC32SHORT || hunk_id == HUNK_DRELOC32 || hunk_id == HUNK_ABSRELOC16) {
            while (1) {
                uint32_t count = OSReadBigInt16(bytes, 0); INCREMENT_PTR(bytes, 2);
                if (count == 0) break;
                uint32_t target_hunk_number = OSReadBigInt16(bytes, 0); INCREMENT_PTR(bytes, 2);
                for (uint32_t i=0; i<count; i++) {
                    uint32_t offset = OSReadBigInt16(bytes, 0); INCREMENT_PTR(bytes, 2);
                    uint32_t original = OSReadBigInt32([currentSegment.mappedData bytes], offset);
                    if (hunk_id == HUNK_ABSRELOC16) {
                        original -= (uint32_t) (currentSegment.startAddress + offset);
                    }
                    original += loadAddresses[target_hunk_number];
                    OSWriteBigInt32((void *)[currentSegment.mappedData bytes], offset, original);
                }
            }
        }
        else if (hunk_id == HUNK_END) {
            currentHunkIndex++;
            if (currentHunkIndex > lastHunk) break;
        }
    }

    file.cpuFamily = @"motorola";
    file.cpuSubFamily = @"68000";
    file.addressSpaceWidthInBits = 32;
    file.integerWidthInBits = 32;

    [file addEntryPoint:firstAddress];

    // Add segment for custom registers and CIA
    [file addSegmentAt:0 size:0x100].segmentName         = @"Page Zero";
    [file addSegmentAt:0xBFE001 size:0x100].segmentName  = @"CIAA";
    [file addSegmentAt:0xBFD000 size:0x100].segmentName  = @"CIAB";
    [file addSegmentAt:0xDFF000 size:0x1000].segmentName = @"Custom";

    // Add some known address
    [file setName:@"CIAA_pra"    forVirtualAddress:0xBFE001 reason:NCReason_Automatic];
    [file setName:@"CIAA_prb"    forVirtualAddress:0xBFE101 reason:NCReason_Automatic];
    [file setName:@"CIAA_ddra"   forVirtualAddress:0xBFE201 reason:NCReason_Automatic];
    [file setName:@"CIAA_ddrb"   forVirtualAddress:0xBFE301 reason:NCReason_Automatic];
    [file setName:@"CIAA_talo"   forVirtualAddress:0xBFE401 reason:NCReason_Automatic];
    [file setName:@"CIAA_tahi"   forVirtualAddress:0xBFE501 reason:NCReason_Automatic];
    [file setName:@"CIAA_tblo"   forVirtualAddress:0xBFE601 reason:NCReason_Automatic];
    [file setName:@"CIAA_tbhi"   forVirtualAddress:0xBFE701 reason:NCReason_Automatic];
    [file setName:@"CIAA_todlo"  forVirtualAddress:0xBFE801 reason:NCReason_Automatic];
    [file setName:@"CIAA_todmid" forVirtualAddress:0xBFE901 reason:NCReason_Automatic];
    [file setName:@"CIAA_todhi"  forVirtualAddress:0xBFEA01 reason:NCReason_Automatic];
    [file setName:@"CIAA_sdr"    forVirtualAddress:0xBFEC01 reason:NCReason_Automatic];
    [file setName:@"CIAA_icr"    forVirtualAddress:0xBFED01 reason:NCReason_Automatic];
    [file setName:@"CIAA_cra"    forVirtualAddress:0xBFEE01 reason:NCReason_Automatic];
    [file setName:@"CIAA_crb"    forVirtualAddress:0xBFEF01 reason:NCReason_Automatic];

    [file setName:@"CIAB_pra"    forVirtualAddress:0xBFD000 reason:NCReason_Automatic];
    [file setName:@"CIAB_prb"    forVirtualAddress:0xBFD100 reason:NCReason_Automatic];
    [file setName:@"CIAB_ddra"   forVirtualAddress:0xBFD200 reason:NCReason_Automatic];
    [file setName:@"CIAB_ddrb"   forVirtualAddress:0xBFD300 reason:NCReason_Automatic];
    [file setName:@"CIAB_talo"   forVirtualAddress:0xBFD400 reason:NCReason_Automatic];
    [file setName:@"CIAB_tahi"   forVirtualAddress:0xBFD500 reason:NCReason_Automatic];
    [file setName:@"CIAB_tblo"   forVirtualAddress:0xBFD600 reason:NCReason_Automatic];
    [file setName:@"CIAB_tbhi"   forVirtualAddress:0xBFD700 reason:NCReason_Automatic];
    [file setName:@"CIAB_todlo"  forVirtualAddress:0xBFD800 reason:NCReason_Automatic];
    [file setName:@"CIAB_todmid" forVirtualAddress:0xBFD900 reason:NCReason_Automatic];
    [file setName:@"CIAB_todhi"  forVirtualAddress:0xBFDA00 reason:NCReason_Automatic];
    [file setName:@"CIAB_sdr"    forVirtualAddress:0xBFDC00 reason:NCReason_Automatic];
    [file setName:@"CIAB_icr"    forVirtualAddress:0xBFDD00 reason:NCReason_Automatic];
    [file setName:@"CIAB_cra"    forVirtualAddress:0xBFDE00 reason:NCReason_Automatic];
    [file setName:@"CIAB_crb"    forVirtualAddress:0xBFDF00 reason:NCReason_Automatic];

    [file setName:@"BLTDDAT" forVirtualAddress:0xDFF000 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter dest. early read (dummy address)" atVirtualAddress:0xDFF000 reason:CCReason_Automatic];
    [file setName:@"DMACONR" forVirtualAddress:0xDFF002 reason:NCReason_Automatic]; [file setInlineComment:@"Dma control (and blitter status) read" atVirtualAddress:0xDFF002 reason:CCReason_Automatic];
    [file setName:@"VPOSR" forVirtualAddress:0xDFF004 reason:NCReason_Automatic]; [file setInlineComment:@"Read vertical most sig. bits (and frame flop)" atVirtualAddress:0xDFF004 reason:CCReason_Automatic];
    [file setName:@"VHPOSR" forVirtualAddress:0xDFF006 reason:NCReason_Automatic]; [file setInlineComment:@"Read vert and horiz position of beam" atVirtualAddress:0xDFF006 reason:CCReason_Automatic];
    [file setName:@"DSKDATR" forVirtualAddress:0xDFF008 reason:NCReason_Automatic]; [file setInlineComment:@"Disk data early read (dummy address)" atVirtualAddress:0xDFF008 reason:CCReason_Automatic];
    [file setName:@"JOY0DAT" forVirtualAddress:0xDFF00A reason:NCReason_Automatic]; [file setInlineComment:@"Joystick-mouse 0 data (vert, horiz)" atVirtualAddress:0xDFF00A reason:CCReason_Automatic];
    [file setName:@"JOY1DAT" forVirtualAddress:0xDFF00C reason:NCReason_Automatic]; [file setInlineComment:@"Joystick-mouse 1 data (vert, horiz)" atVirtualAddress:0xDFF00C reason:CCReason_Automatic];
    [file setName:@"CLXDAT" forVirtualAddress:0xDFF00E reason:NCReason_Automatic]; [file setInlineComment:@"Collision data reg. (read and clear)" atVirtualAddress:0xDFF00E reason:CCReason_Automatic];
    [file setName:@"ADKCONR" forVirtualAddress:0xDFF010 reason:NCReason_Automatic]; [file setInlineComment:@"Audio,disk control register read" atVirtualAddress:0xDFF010 reason:CCReason_Automatic];
    [file setName:@"POT0DAT" forVirtualAddress:0xDFF012 reason:NCReason_Automatic]; [file setInlineComment:@"Pot counter data left pair (vert, horiz)" atVirtualAddress:0xDFF012 reason:CCReason_Automatic];
    [file setName:@"POT1DAT" forVirtualAddress:0xDFF014 reason:NCReason_Automatic]; [file setInlineComment:@"Pot counter data right pair (vert, horiz)" atVirtualAddress:0xDFF014 reason:CCReason_Automatic];
    [file setName:@"POTINP" forVirtualAddress:0xDFF016 reason:NCReason_Automatic]; [file setInlineComment:@"Pot pin data read" atVirtualAddress:0xDFF016 reason:CCReason_Automatic];
    [file setName:@"SERDATR" forVirtualAddress:0xDFF018 reason:NCReason_Automatic]; [file setInlineComment:@"Serial port data and status read" atVirtualAddress:0xDFF018 reason:CCReason_Automatic];
    [file setName:@"DSKBYTR" forVirtualAddress:0xDFF01A reason:NCReason_Automatic]; [file setInlineComment:@"Disk data byte and status read" atVirtualAddress:0xDFF01A reason:CCReason_Automatic];
    [file setName:@"INTENAR" forVirtualAddress:0xDFF01C reason:NCReason_Automatic]; [file setInlineComment:@"Interrupt enable bits read" atVirtualAddress:0xDFF01C reason:CCReason_Automatic];
    [file setName:@"INTREQR" forVirtualAddress:0xDFF01E reason:NCReason_Automatic]; [file setInlineComment:@"Interrupt request bits read" atVirtualAddress:0xDFF01E reason:CCReason_Automatic];
    [file setName:@"DSKPTH" forVirtualAddress:0xDFF020 reason:NCReason_Automatic]; [file setInlineComment:@"Disk pointer (high 5 bits, was 3 bits)" atVirtualAddress:0xDFF020 reason:CCReason_Automatic];
    [file setName:@"DSKPTL" forVirtualAddress:0xDFF022 reason:NCReason_Automatic]; [file setInlineComment:@"Disk pointer (low 15 bits)" atVirtualAddress:0xDFF022 reason:CCReason_Automatic];
    [file setName:@"DSKLEN" forVirtualAddress:0xDFF024 reason:NCReason_Automatic]; [file setInlineComment:@"Disk length" atVirtualAddress:0xDFF024 reason:CCReason_Automatic];
    [file setName:@"DSKDAT" forVirtualAddress:0xDFF026 reason:NCReason_Automatic]; [file setInlineComment:@"Disk DMA data write" atVirtualAddress:0xDFF026 reason:CCReason_Automatic];
    [file setName:@"REFPTR" forVirtualAddress:0xDFF028 reason:NCReason_Automatic]; [file setInlineComment:@"Refresh pointer" atVirtualAddress:0xDFF028 reason:CCReason_Automatic];
    [file setName:@"VPOSW" forVirtualAddress:0xDFF02A reason:NCReason_Automatic]; [file setInlineComment:@"Write vert most sig. bits (and frame flop)" atVirtualAddress:0xDFF02A reason:CCReason_Automatic];
    [file setName:@"VHPOSW" forVirtualAddress:0xDFF02C reason:NCReason_Automatic]; [file setInlineComment:@"Write vert and horiz pos of beam" atVirtualAddress:0xDFF02C reason:CCReason_Automatic];
    [file setName:@"COPCON" forVirtualAddress:0xDFF02E reason:NCReason_Automatic]; [file setInlineComment:@"Coprocessor control" atVirtualAddress:0xDFF02E reason:CCReason_Automatic];
    [file setName:@"SERDAT" forVirtualAddress:0xDFF030 reason:NCReason_Automatic]; [file setInlineComment:@"Serial port data and stop bits write" atVirtualAddress:0xDFF030 reason:CCReason_Automatic];
    [file setName:@"SERPER" forVirtualAddress:0xDFF032 reason:NCReason_Automatic]; [file setInlineComment:@"Serial port period and control" atVirtualAddress:0xDFF032 reason:CCReason_Automatic];
    [file setName:@"POTGO" forVirtualAddress:0xDFF034 reason:NCReason_Automatic]; [file setInlineComment:@"Pot count start,pot pin drive enable data" atVirtualAddress:0xDFF034 reason:CCReason_Automatic];
    [file setName:@"JOYTEST" forVirtualAddress:0xDFF036 reason:NCReason_Automatic]; [file setInlineComment:@"Write to all 4 joystick-mouse counters at once" atVirtualAddress:0xDFF036 reason:CCReason_Automatic];
    [file setName:@"STREQU" forVirtualAddress:0xDFF038 reason:NCReason_Automatic]; [file setInlineComment:@"Strobe for horiz sync with VB and EQU" atVirtualAddress:0xDFF038 reason:CCReason_Automatic];
    [file setName:@"STRVBL" forVirtualAddress:0xDFF03A reason:NCReason_Automatic]; [file setInlineComment:@"Strobe for horiz sync with VB (vert blank)" atVirtualAddress:0xDFF03A reason:CCReason_Automatic];
    [file setName:@"STRHOR" forVirtualAddress:0xDFF03C reason:NCReason_Automatic]; [file setInlineComment:@"Strobe for horiz sync" atVirtualAddress:0xDFF03C reason:CCReason_Automatic];
    [file setName:@"STRLONG" forVirtualAddress:0xDFF03E reason:NCReason_Automatic]; [file setInlineComment:@"Strobe for identification of long horiz line" atVirtualAddress:0xDFF03E reason:CCReason_Automatic];
    [file setName:@"BLTCON0" forVirtualAddress:0xDFF040 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter control register 0" atVirtualAddress:0xDFF040 reason:CCReason_Automatic];
    [file setName:@"BLTCON1" forVirtualAddress:0xDFF042 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter control register 1" atVirtualAddress:0xDFF042 reason:CCReason_Automatic];
    [file setName:@"BLTAFWM" forVirtualAddress:0xDFF044 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter first word mask for source A" atVirtualAddress:0xDFF044 reason:CCReason_Automatic];
    [file setName:@"BLTALWM" forVirtualAddress:0xDFF046 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter last word mask for source A" atVirtualAddress:0xDFF046 reason:CCReason_Automatic];
    [file setName:@"BLTCPTH" forVirtualAddress:0xDFF048 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter pointer to source C (high 5 bits, was 3 bits)" atVirtualAddress:0xDFF048 reason:CCReason_Automatic];
    [file setName:@"BLTCPTL" forVirtualAddress:0xDFF04A reason:NCReason_Automatic]; [file setInlineComment:@"Blitter pointer to source C (low 15 bits)" atVirtualAddress:0xDFF04A reason:CCReason_Automatic];
    [file setName:@"BLTBPTH" forVirtualAddress:0xDFF04C reason:NCReason_Automatic]; [file setInlineComment:@"Blitter pointer to source B (high 5 bits, was 3 bits)" atVirtualAddress:0xDFF04C reason:CCReason_Automatic];
    [file setName:@"BLTBPTL" forVirtualAddress:0xDFF04E reason:NCReason_Automatic]; [file setInlineComment:@"Blitter pointer to source B (low 15 bits)" atVirtualAddress:0xDFF04E reason:CCReason_Automatic];
    [file setName:@"BLTAPTH" forVirtualAddress:0xDFF050 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter pointer to source A (high 5 bits, was 3 bits)" atVirtualAddress:0xDFF050 reason:CCReason_Automatic];
    [file setName:@"BLTAPTL" forVirtualAddress:0xDFF052 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter pointer to source A (low 15 bits)" atVirtualAddress:0xDFF052 reason:CCReason_Automatic];
    [file setName:@"BLTDPTH" forVirtualAddress:0xDFF054 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter pointer to dest D (high 5 bits, was 3 bits)" atVirtualAddress:0xDFF054 reason:CCReason_Automatic];
    [file setName:@"BLTDPTL" forVirtualAddress:0xDFF056 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter pointer to dest D (low 15 bits)" atVirtualAddress:0xDFF056 reason:CCReason_Automatic];
    [file setName:@"BLTSIZE" forVirtualAddress:0xDFF058 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter start and size (win/width,height)" atVirtualAddress:0xDFF058 reason:CCReason_Automatic];
    [file setName:@"BLTCON0L" forVirtualAddress:0xDFF05A reason:NCReason_Automatic]; [file setInlineComment:@"Blitter control 0, lower 8 bits (minterms)" atVirtualAddress:0xDFF05A reason:CCReason_Automatic];
    [file setName:@"BLTSIZV" forVirtualAddress:0xDFF05C reason:NCReason_Automatic]; [file setInlineComment:@"Blitter V size (for 15 bit vertical size)" atVirtualAddress:0xDFF05C reason:CCReason_Automatic];
    [file setName:@"BLTSIZH" forVirtualAddress:0xDFF05E reason:NCReason_Automatic]; [file setInlineComment:@"Blitter H size and start (for 11 bit H size)" atVirtualAddress:0xDFF05E reason:CCReason_Automatic];
    [file setName:@"BLTCMOD" forVirtualAddress:0xDFF060 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter modulo for source C" atVirtualAddress:0xDFF060 reason:CCReason_Automatic];
    [file setName:@"BLTBMOD" forVirtualAddress:0xDFF062 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter modulo for source B" atVirtualAddress:0xDFF062 reason:CCReason_Automatic];
    [file setName:@"BLTAMOD" forVirtualAddress:0xDFF064 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter modulo for source A" atVirtualAddress:0xDFF064 reason:CCReason_Automatic];
    [file setName:@"BLTDMOD" forVirtualAddress:0xDFF066 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter modulo for dest D" atVirtualAddress:0xDFF066 reason:CCReason_Automatic];
    [file setName:@"BLTCDAT" forVirtualAddress:0xDFF070 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter source C data register" atVirtualAddress:0xDFF070 reason:CCReason_Automatic];
    [file setName:@"BLTBDAT" forVirtualAddress:0xDFF072 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter source B data register" atVirtualAddress:0xDFF072 reason:CCReason_Automatic];
    [file setName:@"BLTADAT" forVirtualAddress:0xDFF074 reason:NCReason_Automatic]; [file setInlineComment:@"Blitter source A data register" atVirtualAddress:0xDFF074 reason:CCReason_Automatic];
    [file setName:@"SPRHDAT" forVirtualAddress:0xDFF078 reason:NCReason_Automatic]; [file setInlineComment:@"Ext. logic UHRES sprite pointer and data identifier" atVirtualAddress:0xDFF078 reason:CCReason_Automatic];
    [file setName:@"BPLHDAT" forVirtualAddress:0xDFF07A reason:NCReason_Automatic]; [file setInlineComment:@"Ext. logic UHRES bit plane identifier" atVirtualAddress:0xDFF07A reason:CCReason_Automatic];
    [file setName:@"DENISEID" forVirtualAddress:0xDFF07C reason:NCReason_Automatic]; [file setInlineComment:@"Chip revision level for Denise/Lisa (video out chip)" atVirtualAddress:0xDFF07C reason:CCReason_Automatic];
    [file setName:@"DSKSYNC" forVirtualAddress:0xDFF07E reason:NCReason_Automatic]; [file setInlineComment:@"Disk sync pattern reg for disk read" atVirtualAddress:0xDFF07E reason:CCReason_Automatic];
    [file setName:@"COP1LCH" forVirtualAddress:0xDFF080 reason:NCReason_Automatic]; [file setInlineComment:@"Coprocessor 1st location (high 5 bits,was 3 bits)" atVirtualAddress:0xDFF080 reason:CCReason_Automatic];
    [file setName:@"COP1LCL" forVirtualAddress:0xDFF082 reason:NCReason_Automatic]; [file setInlineComment:@"Coprocessor 1st location (low 15 bits)" atVirtualAddress:0xDFF082 reason:CCReason_Automatic];
    [file setName:@"COP2LCH" forVirtualAddress:0xDFF084 reason:NCReason_Automatic]; [file setInlineComment:@"Coprocessor 2nd location(high 5 bits,was 3 bits)" atVirtualAddress:0xDFF084 reason:CCReason_Automatic];
    [file setName:@"COP2LCL" forVirtualAddress:0xDFF086 reason:NCReason_Automatic]; [file setInlineComment:@"Coprocessor 2nd location (low 15 bits)" atVirtualAddress:0xDFF086 reason:CCReason_Automatic];
    [file setName:@"COPJMP1" forVirtualAddress:0xDFF088 reason:NCReason_Automatic]; [file setInlineComment:@"Coprocessor restart at 1st location" atVirtualAddress:0xDFF088 reason:CCReason_Automatic];
    [file setName:@"COPJMP2" forVirtualAddress:0xDFF08A reason:NCReason_Automatic]; [file setInlineComment:@"Coprocessor restart at 2nd location" atVirtualAddress:0xDFF08A reason:CCReason_Automatic];
    [file setName:@"COPINS" forVirtualAddress:0xDFF08C reason:NCReason_Automatic]; [file setInlineComment:@"Coprocessor inst fetch identify" atVirtualAddress:0xDFF08C reason:CCReason_Automatic];
    [file setName:@"DIWSTRT" forVirtualAddress:0xDFF08E reason:NCReason_Automatic]; [file setInlineComment:@"Display window start (upper left vert,horiz pos)" atVirtualAddress:0xDFF08E reason:CCReason_Automatic];
    [file setName:@"DIWSTOP" forVirtualAddress:0xDFF090 reason:NCReason_Automatic]; [file setInlineComment:@"Display window stop (lower right vert,horiz pos)" atVirtualAddress:0xDFF090 reason:CCReason_Automatic];
    [file setName:@"DDFSTRT" forVirtualAddress:0xDFF092 reason:NCReason_Automatic]; [file setInlineComment:@"Display bit plane data fetch start,horiz pos" atVirtualAddress:0xDFF092 reason:CCReason_Automatic];
    [file setName:@"DDFSTOP" forVirtualAddress:0xDFF094 reason:NCReason_Automatic]; [file setInlineComment:@"Display bit plane data fetch stop,horiz pos" atVirtualAddress:0xDFF094 reason:CCReason_Automatic];
    [file setName:@"DMACON" forVirtualAddress:0xDFF096 reason:NCReason_Automatic]; [file setInlineComment:@"DMA control write (clear or set)" atVirtualAddress:0xDFF096 reason:CCReason_Automatic];
    [file setName:@"CLXCON" forVirtualAddress:0xDFF098 reason:NCReason_Automatic]; [file setInlineComment:@"Collision control" atVirtualAddress:0xDFF098 reason:CCReason_Automatic];
    [file setName:@"INTENA" forVirtualAddress:0xDFF09A reason:NCReason_Automatic]; [file setInlineComment:@"Interrupt enable bits (clear or set bits)" atVirtualAddress:0xDFF09A reason:CCReason_Automatic];
    [file setName:@"INTREQ" forVirtualAddress:0xDFF09C reason:NCReason_Automatic]; [file setInlineComment:@"Interrupt request bits (clear or set bits)" atVirtualAddress:0xDFF09C reason:CCReason_Automatic];
    [file setName:@"ADKCON" forVirtualAddress:0xDFF09E reason:NCReason_Automatic]; [file setInlineComment:@"Audio,disk,UART control" atVirtualAddress:0xDFF09E reason:CCReason_Automatic];
    [file setName:@"AUD0LCH" forVirtualAddress:0xDFF0A0 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 0 location (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0A0 reason:CCReason_Automatic];
    [file setName:@"AUD0LCL" forVirtualAddress:0xDFF0A2 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 0 location (low 15 bits)" atVirtualAddress:0xDFF0A2 reason:CCReason_Automatic];
    [file setName:@"AUD0LEN" forVirtualAddress:0xDFF0A4 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 0 length" atVirtualAddress:0xDFF0A4 reason:CCReason_Automatic];
    [file setName:@"AUD0PER" forVirtualAddress:0xDFF0A6 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 0 period" atVirtualAddress:0xDFF0A6 reason:CCReason_Automatic];
    [file setName:@"AUD0VOL" forVirtualAddress:0xDFF0A8 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 0 volume" atVirtualAddress:0xDFF0A8 reason:CCReason_Automatic];
    [file setName:@"AUD0DAT" forVirtualAddress:0xDFF0AA reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 0 data" atVirtualAddress:0xDFF0AA reason:CCReason_Automatic];
    [file setName:@"AUD1LCH" forVirtualAddress:0xDFF0B0 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 1 location (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0B0 reason:CCReason_Automatic];
    [file setName:@"AUD1LCL" forVirtualAddress:0xDFF0B2 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 1 location (low 15 bits)" atVirtualAddress:0xDFF0B2 reason:CCReason_Automatic];
    [file setName:@"AUD1LEN" forVirtualAddress:0xDFF0B4 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 1 length" atVirtualAddress:0xDFF0B4 reason:CCReason_Automatic];
    [file setName:@"AUD1PER" forVirtualAddress:0xDFF0B6 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 1 period" atVirtualAddress:0xDFF0B6 reason:CCReason_Automatic];
    [file setName:@"AUD1VOL" forVirtualAddress:0xDFF0B8 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 1 volume" atVirtualAddress:0xDFF0B8 reason:CCReason_Automatic];
    [file setName:@"AUD1DAT" forVirtualAddress:0xDFF0BA reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 1 data" atVirtualAddress:0xDFF0BA reason:CCReason_Automatic];
    [file setName:@"AUD2LCH" forVirtualAddress:0xDFF0C0 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 2 location (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0C0 reason:CCReason_Automatic];
    [file setName:@"AUD2LCL" forVirtualAddress:0xDFF0C2 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 2 location (low 15 bits)" atVirtualAddress:0xDFF0C2 reason:CCReason_Automatic];
    [file setName:@"AUD2LEN" forVirtualAddress:0xDFF0C4 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 2 length" atVirtualAddress:0xDFF0C4 reason:CCReason_Automatic];
    [file setName:@"AUD2PER" forVirtualAddress:0xDFF0C6 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 2 period" atVirtualAddress:0xDFF0C6 reason:CCReason_Automatic];
    [file setName:@"AUD2VOL" forVirtualAddress:0xDFF0C8 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 2 volume" atVirtualAddress:0xDFF0C8 reason:CCReason_Automatic];
    [file setName:@"AUD2DAT" forVirtualAddress:0xDFF0CA reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 2 data" atVirtualAddress:0xDFF0CA reason:CCReason_Automatic];
    [file setName:@"AUD3LCH" forVirtualAddress:0xDFF0D0 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 3 location (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0D0 reason:CCReason_Automatic];
    [file setName:@"AUD3LCL" forVirtualAddress:0xDFF0D2 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 3 location (low 15 bits)" atVirtualAddress:0xDFF0D2 reason:CCReason_Automatic];
    [file setName:@"AUD3LEN" forVirtualAddress:0xDFF0D4 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 3 length" atVirtualAddress:0xDFF0D4 reason:CCReason_Automatic];
    [file setName:@"AUD3PER" forVirtualAddress:0xDFF0D6 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 3 period" atVirtualAddress:0xDFF0D6 reason:CCReason_Automatic];
    [file setName:@"AUD3VOL" forVirtualAddress:0xDFF0D8 reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 3 volume" atVirtualAddress:0xDFF0D8 reason:CCReason_Automatic];
    [file setName:@"AUD3DAT" forVirtualAddress:0xDFF0DA reason:NCReason_Automatic]; [file setInlineComment:@"Audio channel 3 data" atVirtualAddress:0xDFF0DA reason:CCReason_Automatic];
    [file setName:@"BPL1PTH" forVirtualAddress:0xDFF0E0 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 1 (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0E0 reason:CCReason_Automatic];
    [file setName:@"BPL1PTL" forVirtualAddress:0xDFF0E2 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 1 (low 15 bits)" atVirtualAddress:0xDFF0E2 reason:CCReason_Automatic];
    [file setName:@"BPL2PTH" forVirtualAddress:0xDFF0E4 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 2 (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0E4 reason:CCReason_Automatic];
    [file setName:@"BPL2PTL" forVirtualAddress:0xDFF0E6 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 2 (low 15 bits)" atVirtualAddress:0xDFF0E6 reason:CCReason_Automatic];
    [file setName:@"BPL3PTH" forVirtualAddress:0xDFF0E8 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 3 (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0E8 reason:CCReason_Automatic];
    [file setName:@"BPL3PTL" forVirtualAddress:0xDFF0EA reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 3 (low 15 bits)" atVirtualAddress:0xDFF0EA reason:CCReason_Automatic];
    [file setName:@"BPL4PTH" forVirtualAddress:0xDFF0EC reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 4 (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0EC reason:CCReason_Automatic];
    [file setName:@"BPL4PTL" forVirtualAddress:0xDFF0EE reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 4 (low 15 bits)" atVirtualAddress:0xDFF0EE reason:CCReason_Automatic];
    [file setName:@"BPL5PTH" forVirtualAddress:0xDFF0F0 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 5 (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0F0 reason:CCReason_Automatic];
    [file setName:@"BPL5PTL" forVirtualAddress:0xDFF0F2 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 5 (low 15 bits)" atVirtualAddress:0xDFF0F2 reason:CCReason_Automatic];
    [file setName:@"BPL6PTH" forVirtualAddress:0xDFF0F4 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 6 (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0F4 reason:CCReason_Automatic];
    [file setName:@"BPL6PTL" forVirtualAddress:0xDFF0F6 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane pointer 6 (low 15 bits)" atVirtualAddress:0xDFF0F6 reason:CCReason_Automatic];
    [file setName:@"BPL7PTH" forVirtualAddress:0xDFF0F8 reason:NCReason_Automatic]; [file setInlineComment:@"pointer 7 (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0F8 reason:CCReason_Automatic];
    [file setName:@"BPL7PTL" forVirtualAddress:0xDFF0FA reason:NCReason_Automatic]; [file setInlineComment:@"pointer 7 (low 15 bits)" atVirtualAddress:0xDFF0FA reason:CCReason_Automatic];
    [file setName:@"BPL8PTH" forVirtualAddress:0xDFF0FC reason:NCReason_Automatic]; [file setInlineComment:@"pointer 8 (high 5 bits was 3 bits)" atVirtualAddress:0xDFF0FC reason:CCReason_Automatic];
    [file setName:@"BPL8PTL" forVirtualAddress:0xDFF0FE reason:NCReason_Automatic]; [file setInlineComment:@"pointer 8 (low 15 bits)" atVirtualAddress:0xDFF0FE reason:CCReason_Automatic];
    [file setName:@"BPLCON0" forVirtualAddress:0xDFF100 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane control (miscellaneous control bits)" atVirtualAddress:0xDFF100 reason:CCReason_Automatic];
    [file setName:@"BPLCON1" forVirtualAddress:0xDFF102 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane control (scroll value)" atVirtualAddress:0xDFF102 reason:CCReason_Automatic];
    [file setName:@"BPLCON2" forVirtualAddress:0xDFF104 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane control (video priority control)" atVirtualAddress:0xDFF104 reason:CCReason_Automatic];
    [file setName:@"BPLCON3" forVirtualAddress:0xDFF106 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane control (enhanced features)" atVirtualAddress:0xDFF106 reason:CCReason_Automatic];
    [file setName:@"BPL1MOD" forVirtualAddress:0xDFF108 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane modulo (odd planes)" atVirtualAddress:0xDFF108 reason:CCReason_Automatic];
    [file setName:@"BPL2MOD" forVirtualAddress:0xDFF10A reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane modulo (even planes)" atVirtualAddress:0xDFF10A reason:CCReason_Automatic];
    [file setName:@"BPLCON4" forVirtualAddress:0xDFF10C reason:NCReason_Automatic]; [file setInlineComment:@"control (bitplane and sprite-masks)" atVirtualAddress:0xDFF10C reason:CCReason_Automatic];
    [file setName:@"CLXCON2" forVirtualAddress:0xDFF10E reason:NCReason_Automatic]; [file setInlineComment:@"collision control" atVirtualAddress:0xDFF10E reason:CCReason_Automatic];
    [file setName:@"BPL1DAT" forVirtualAddress:0xDFF110 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane 1 data (parallel to serial convert)" atVirtualAddress:0xDFF110 reason:CCReason_Automatic];
    [file setName:@"BPL2DAT" forVirtualAddress:0xDFF112 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane 2 data (parallel to serial convert)" atVirtualAddress:0xDFF112 reason:CCReason_Automatic];
    [file setName:@"BPL3DAT" forVirtualAddress:0xDFF114 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane 3 data (parallel to serial convert)" atVirtualAddress:0xDFF114 reason:CCReason_Automatic];
    [file setName:@"BPL4DAT" forVirtualAddress:0xDFF116 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane 4 data (parallel to serial convert)" atVirtualAddress:0xDFF116 reason:CCReason_Automatic];
    [file setName:@"BPL5DAT" forVirtualAddress:0xDFF118 reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane 5 data (parallel to serial convert)" atVirtualAddress:0xDFF118 reason:CCReason_Automatic];
    [file setName:@"BPL6DAT" forVirtualAddress:0xDFF11A reason:NCReason_Automatic]; [file setInlineComment:@"Bitplane 6 data (parallel to serial convert)" atVirtualAddress:0xDFF11A reason:CCReason_Automatic];
    [file setName:@"BPL7DAT" forVirtualAddress:0xDFF11C reason:NCReason_Automatic]; [file setInlineComment:@"7 data (parallel to serial convert)" atVirtualAddress:0xDFF11C reason:CCReason_Automatic];
    [file setName:@"BPL8DAT" forVirtualAddress:0xDFF11E reason:NCReason_Automatic]; [file setInlineComment:@"8 data (parallel to serial convert)" atVirtualAddress:0xDFF11E reason:CCReason_Automatic];
    [file setName:@"SPR0PTH" forVirtualAddress:0xDFF120 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 0 pointer (high 5 bits was 3 bits)" atVirtualAddress:0xDFF120 reason:CCReason_Automatic];
    [file setName:@"SPR0PTL" forVirtualAddress:0xDFF122 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 0 pointer (low 15 bits)" atVirtualAddress:0xDFF122 reason:CCReason_Automatic];
    [file setName:@"SPR1PTH" forVirtualAddress:0xDFF124 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 1 pointer (high 5 bits was 3 bits)" atVirtualAddress:0xDFF124 reason:CCReason_Automatic];
    [file setName:@"SPR1PTL" forVirtualAddress:0xDFF126 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 1 pointer (low 15 bits)" atVirtualAddress:0xDFF126 reason:CCReason_Automatic];
    [file setName:@"SPR2PTH" forVirtualAddress:0xDFF128 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 2 pointer (high 5 bits was 3 bits)" atVirtualAddress:0xDFF128 reason:CCReason_Automatic];
    [file setName:@"SPR2PTL" forVirtualAddress:0xDFF12A reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 2 pointer (low 15 bits)" atVirtualAddress:0xDFF12A reason:CCReason_Automatic];
    [file setName:@"SPR3PTH" forVirtualAddress:0xDFF12C reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 3 pointer (high 5 bits was 3 bits)" atVirtualAddress:0xDFF12C reason:CCReason_Automatic];
    [file setName:@"SPR3PTL" forVirtualAddress:0xDFF12E reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 3 pointer (low 15 bits)" atVirtualAddress:0xDFF12E reason:CCReason_Automatic];
    [file setName:@"SPR4PTH" forVirtualAddress:0xDFF130 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 4 pointer (high 5 bits was 3 bits)" atVirtualAddress:0xDFF130 reason:CCReason_Automatic];
    [file setName:@"SPR4PTL" forVirtualAddress:0xDFF132 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 4 pointer (low 15 bits)" atVirtualAddress:0xDFF132 reason:CCReason_Automatic];
    [file setName:@"SPR5PTH" forVirtualAddress:0xDFF134 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 5 pointer (high 5 bits was 3 bits)" atVirtualAddress:0xDFF134 reason:CCReason_Automatic];
    [file setName:@"SPR5PTL" forVirtualAddress:0xDFF136 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 5 pointer (low 15 bits)" atVirtualAddress:0xDFF136 reason:CCReason_Automatic];
    [file setName:@"SPR6PTH" forVirtualAddress:0xDFF138 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 6 pointer (high 5 bits was 3 bits)" atVirtualAddress:0xDFF138 reason:CCReason_Automatic];
    [file setName:@"SPR6PTL" forVirtualAddress:0xDFF13A reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 6 pointer (low 15 bits)" atVirtualAddress:0xDFF13A reason:CCReason_Automatic];
    [file setName:@"SPR7PTH" forVirtualAddress:0xDFF13C reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 7 pointer (high 5 bits was 3 bits)" atVirtualAddress:0xDFF13C reason:CCReason_Automatic];
    [file setName:@"SPR7PTL" forVirtualAddress:0xDFF13E reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 7 pointer (low 15 bits)" atVirtualAddress:0xDFF13E reason:CCReason_Automatic];
    [file setName:@"SPR0POS" forVirtualAddress:0xDFF140 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 0 vert,horiz start pos data" atVirtualAddress:0xDFF140 reason:CCReason_Automatic];
    [file setName:@"SPR0CTL" forVirtualAddress:0xDFF142 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 0 position and control data" atVirtualAddress:0xDFF142 reason:CCReason_Automatic];
    [file setName:@"SPR0DATA" forVirtualAddress:0xDFF144 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 0 image data register A" atVirtualAddress:0xDFF144 reason:CCReason_Automatic];
    [file setName:@"SPR0DATB" forVirtualAddress:0xDFF146 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 0 image data register B" atVirtualAddress:0xDFF146 reason:CCReason_Automatic];
    [file setName:@"SPR1POS" forVirtualAddress:0xDFF148 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 1 vert,horiz start pos data" atVirtualAddress:0xDFF148 reason:CCReason_Automatic];
    [file setName:@"SPR1CTL" forVirtualAddress:0xDFF14A reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 1 position and control data" atVirtualAddress:0xDFF14A reason:CCReason_Automatic];
    [file setName:@"SPR1DATA" forVirtualAddress:0xDFF14C reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 1 image data register A" atVirtualAddress:0xDFF14C reason:CCReason_Automatic];
    [file setName:@"SPR1DATB" forVirtualAddress:0xDFF14E reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 1 image data register B" atVirtualAddress:0xDFF14E reason:CCReason_Automatic];
    [file setName:@"SPR2POS" forVirtualAddress:0xDFF150 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 2 vert,horiz start pos data" atVirtualAddress:0xDFF150 reason:CCReason_Automatic];
    [file setName:@"SPR2CTL" forVirtualAddress:0xDFF152 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 2 position and control data" atVirtualAddress:0xDFF152 reason:CCReason_Automatic];
    [file setName:@"SPR2DATA" forVirtualAddress:0xDFF154 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 2 image data register A" atVirtualAddress:0xDFF154 reason:CCReason_Automatic];
    [file setName:@"SPR2DATB" forVirtualAddress:0xDFF156 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 2 image data register B" atVirtualAddress:0xDFF156 reason:CCReason_Automatic];
    [file setName:@"SPR3POS" forVirtualAddress:0xDFF158 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 3 vert,horiz start pos data" atVirtualAddress:0xDFF158 reason:CCReason_Automatic];
    [file setName:@"SPR3CTL" forVirtualAddress:0xDFF15A reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 3 position and control data" atVirtualAddress:0xDFF15A reason:CCReason_Automatic];
    [file setName:@"SPR3DATA" forVirtualAddress:0xDFF15C reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 3 image data register A" atVirtualAddress:0xDFF15C reason:CCReason_Automatic];
    [file setName:@"SPR3DATB" forVirtualAddress:0xDFF15E reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 3 image data register B" atVirtualAddress:0xDFF15E reason:CCReason_Automatic];
    [file setName:@"SPR4POS" forVirtualAddress:0xDFF160 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 4 vert,horiz start pos data" atVirtualAddress:0xDFF160 reason:CCReason_Automatic];
    [file setName:@"SPR4CTL" forVirtualAddress:0xDFF162 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 4 position and control data" atVirtualAddress:0xDFF162 reason:CCReason_Automatic];
    [file setName:@"SPR4DATA" forVirtualAddress:0xDFF164 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 4 image data register A" atVirtualAddress:0xDFF164 reason:CCReason_Automatic];
    [file setName:@"SPR4DATB" forVirtualAddress:0xDFF166 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 4 image data register B" atVirtualAddress:0xDFF166 reason:CCReason_Automatic];
    [file setName:@"SPR5POS" forVirtualAddress:0xDFF168 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 5 vert,horiz start pos data" atVirtualAddress:0xDFF168 reason:CCReason_Automatic];
    [file setName:@"SPR5CTL" forVirtualAddress:0xDFF16A reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 5 position and control data" atVirtualAddress:0xDFF16A reason:CCReason_Automatic];
    [file setName:@"SPR5DATA" forVirtualAddress:0xDFF16C reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 5 image data register A" atVirtualAddress:0xDFF16C reason:CCReason_Automatic];
    [file setName:@"SPR5DATB" forVirtualAddress:0xDFF16E reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 5 image data register B" atVirtualAddress:0xDFF16E reason:CCReason_Automatic];
    [file setName:@"SPR6POS" forVirtualAddress:0xDFF170 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 6 vert,horiz start pos data" atVirtualAddress:0xDFF170 reason:CCReason_Automatic];
    [file setName:@"SPR6CTL" forVirtualAddress:0xDFF172 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 6 position and control data" atVirtualAddress:0xDFF172 reason:CCReason_Automatic];
    [file setName:@"SPR6DATA" forVirtualAddress:0xDFF174 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 6 image data register A" atVirtualAddress:0xDFF174 reason:CCReason_Automatic];
    [file setName:@"SPR6DATB" forVirtualAddress:0xDFF176 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 6 image data register B" atVirtualAddress:0xDFF176 reason:CCReason_Automatic];
    [file setName:@"SPR7POS" forVirtualAddress:0xDFF178 reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 7 vert,horiz start pos data" atVirtualAddress:0xDFF178 reason:CCReason_Automatic];
    [file setName:@"SPR7CTL" forVirtualAddress:0xDFF17A reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 7 position and control data" atVirtualAddress:0xDFF17A reason:CCReason_Automatic];
    [file setName:@"SPR7DATA" forVirtualAddress:0xDFF17C reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 7 image data register A" atVirtualAddress:0xDFF17C reason:CCReason_Automatic];
    [file setName:@"SPR7DATB" forVirtualAddress:0xDFF17E reason:NCReason_Automatic]; [file setInlineComment:@"Sprite 7 image data register B" atVirtualAddress:0xDFF17E reason:CCReason_Automatic];
    [file setName:@"COLOR00" forVirtualAddress:0xDFF180 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 0" atVirtualAddress:0xDFF180 reason:CCReason_Automatic];
    [file setName:@"COLOR01" forVirtualAddress:0xDFF182 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 1" atVirtualAddress:0xDFF182 reason:CCReason_Automatic];
    [file setName:@"COLOR02" forVirtualAddress:0xDFF184 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 2" atVirtualAddress:0xDFF184 reason:CCReason_Automatic];
    [file setName:@"COLOR03" forVirtualAddress:0xDFF186 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 3" atVirtualAddress:0xDFF186 reason:CCReason_Automatic];
    [file setName:@"COLOR04" forVirtualAddress:0xDFF188 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 4" atVirtualAddress:0xDFF188 reason:CCReason_Automatic];
    [file setName:@"COLOR05" forVirtualAddress:0xDFF18A reason:NCReason_Automatic]; [file setInlineComment:@"Color table 5" atVirtualAddress:0xDFF18A reason:CCReason_Automatic];
    [file setName:@"COLOR06" forVirtualAddress:0xDFF18C reason:NCReason_Automatic]; [file setInlineComment:@"Color table 6" atVirtualAddress:0xDFF18C reason:CCReason_Automatic];
    [file setName:@"COLOR07" forVirtualAddress:0xDFF18E reason:NCReason_Automatic]; [file setInlineComment:@"Color table 7" atVirtualAddress:0xDFF18E reason:CCReason_Automatic];
    [file setName:@"COLOR08" forVirtualAddress:0xDFF190 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 8" atVirtualAddress:0xDFF190 reason:CCReason_Automatic];
    [file setName:@"COLOR09" forVirtualAddress:0xDFF192 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 9" atVirtualAddress:0xDFF192 reason:CCReason_Automatic];
    [file setName:@"COLOR10" forVirtualAddress:0xDFF194 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 10" atVirtualAddress:0xDFF194 reason:CCReason_Automatic];
    [file setName:@"COLOR11" forVirtualAddress:0xDFF196 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 11" atVirtualAddress:0xDFF196 reason:CCReason_Automatic];
    [file setName:@"COLOR12" forVirtualAddress:0xDFF198 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 12" atVirtualAddress:0xDFF198 reason:CCReason_Automatic];
    [file setName:@"COLOR13" forVirtualAddress:0xDFF19A reason:NCReason_Automatic]; [file setInlineComment:@"Color table 13" atVirtualAddress:0xDFF19A reason:CCReason_Automatic];
    [file setName:@"COLOR14" forVirtualAddress:0xDFF19C reason:NCReason_Automatic]; [file setInlineComment:@"Color table 14" atVirtualAddress:0xDFF19C reason:CCReason_Automatic];
    [file setName:@"COLOR15" forVirtualAddress:0xDFF19E reason:NCReason_Automatic]; [file setInlineComment:@"Color table 15" atVirtualAddress:0xDFF19E reason:CCReason_Automatic];
    [file setName:@"COLOR16" forVirtualAddress:0xDFF1A0 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 16" atVirtualAddress:0xDFF1A0 reason:CCReason_Automatic];
    [file setName:@"COLOR17" forVirtualAddress:0xDFF1A2 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 17" atVirtualAddress:0xDFF1A2 reason:CCReason_Automatic];
    [file setName:@"COLOR18" forVirtualAddress:0xDFF1A4 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 18" atVirtualAddress:0xDFF1A4 reason:CCReason_Automatic];
    [file setName:@"COLOR19" forVirtualAddress:0xDFF1A6 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 19" atVirtualAddress:0xDFF1A6 reason:CCReason_Automatic];
    [file setName:@"COLOR20" forVirtualAddress:0xDFF1A8 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 20" atVirtualAddress:0xDFF1A8 reason:CCReason_Automatic];
    [file setName:@"COLOR21" forVirtualAddress:0xDFF1AA reason:NCReason_Automatic]; [file setInlineComment:@"Color table 21" atVirtualAddress:0xDFF1AA reason:CCReason_Automatic];
    [file setName:@"COLOR22" forVirtualAddress:0xDFF1AC reason:NCReason_Automatic]; [file setInlineComment:@"Color table 22" atVirtualAddress:0xDFF1AC reason:CCReason_Automatic];
    [file setName:@"COLOR23" forVirtualAddress:0xDFF1AE reason:NCReason_Automatic]; [file setInlineComment:@"Color table 23" atVirtualAddress:0xDFF1AE reason:CCReason_Automatic];
    [file setName:@"COLOR24" forVirtualAddress:0xDFF1B0 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 24" atVirtualAddress:0xDFF1B0 reason:CCReason_Automatic];
    [file setName:@"COLOR25" forVirtualAddress:0xDFF1B2 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 25" atVirtualAddress:0xDFF1B2 reason:CCReason_Automatic];
    [file setName:@"COLOR26" forVirtualAddress:0xDFF1B4 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 26" atVirtualAddress:0xDFF1B4 reason:CCReason_Automatic];
    [file setName:@"COLOR27" forVirtualAddress:0xDFF1B6 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 27" atVirtualAddress:0xDFF1B6 reason:CCReason_Automatic];
    [file setName:@"COLOR28" forVirtualAddress:0xDFF1B8 reason:NCReason_Automatic]; [file setInlineComment:@"Color table 28" atVirtualAddress:0xDFF1B8 reason:CCReason_Automatic];
    [file setName:@"COLOR29" forVirtualAddress:0xDFF1BA reason:NCReason_Automatic]; [file setInlineComment:@"Color table 29" atVirtualAddress:0xDFF1BA reason:CCReason_Automatic];
    [file setName:@"COLOR30" forVirtualAddress:0xDFF1BC reason:NCReason_Automatic]; [file setInlineComment:@"Color table 30" atVirtualAddress:0xDFF1BC reason:CCReason_Automatic];
    [file setName:@"COLOR31" forVirtualAddress:0xDFF1BE reason:NCReason_Automatic]; [file setInlineComment:@"Color table 31" atVirtualAddress:0xDFF1BE reason:CCReason_Automatic];
    [file setName:@"HTOTAL" forVirtualAddress:0xDFF1C0 reason:NCReason_Automatic]; [file setInlineComment:@"Highest number count, horiz line (VARBEAMEN=1)" atVirtualAddress:0xDFF1C0 reason:CCReason_Automatic];
    [file setName:@"HSSTOP" forVirtualAddress:0xDFF1C2 reason:NCReason_Automatic]; [file setInlineComment:@"Horizontal line position for HSYNC stop" atVirtualAddress:0xDFF1C2 reason:CCReason_Automatic];
    [file setName:@"HBSTRT" forVirtualAddress:0xDFF1C4 reason:NCReason_Automatic]; [file setInlineComment:@"Horizontal line position for HBLANK start" atVirtualAddress:0xDFF1C4 reason:CCReason_Automatic];
    [file setName:@"HBSTOP" forVirtualAddress:0xDFF1C6 reason:NCReason_Automatic]; [file setInlineComment:@"Horizontal line position for HBLANK stop" atVirtualAddress:0xDFF1C6 reason:CCReason_Automatic];
    [file setName:@"VTOTAL" forVirtualAddress:0xDFF1C8 reason:NCReason_Automatic]; [file setInlineComment:@"Highest numbered vertical line (VARBEAMEN=1)" atVirtualAddress:0xDFF1C8 reason:CCReason_Automatic];
    [file setName:@"VSSTOP" forVirtualAddress:0xDFF1CA reason:NCReason_Automatic]; [file setInlineComment:@"Vertical line position for VSYNC stop" atVirtualAddress:0xDFF1CA reason:CCReason_Automatic];
    [file setName:@"VBSTRT" forVirtualAddress:0xDFF1CC reason:NCReason_Automatic]; [file setInlineComment:@"Vertical line for VBLANK start" atVirtualAddress:0xDFF1CC reason:CCReason_Automatic];
    [file setName:@"VBSTOP" forVirtualAddress:0xDFF1CE reason:NCReason_Automatic]; [file setInlineComment:@"Vertical line for VBLANK stop" atVirtualAddress:0xDFF1CE reason:CCReason_Automatic];
    [file setName:@"SPRHSTRT" forVirtualAddress:0xDFF1D0 reason:NCReason_Automatic]; [file setInlineComment:@"UHRES sprite vertical start" atVirtualAddress:0xDFF1D0 reason:CCReason_Automatic];
    [file setName:@"SPRHSTOP" forVirtualAddress:0xDFF1D2 reason:NCReason_Automatic]; [file setInlineComment:@"UHRES sprite vertical stop" atVirtualAddress:0xDFF1D2 reason:CCReason_Automatic];
    [file setName:@"BPLHSTRT" forVirtualAddress:0xDFF1D4 reason:NCReason_Automatic]; [file setInlineComment:@"UHRES bit plane vertical start" atVirtualAddress:0xDFF1D4 reason:CCReason_Automatic];
    [file setName:@"BPLHSTOP" forVirtualAddress:0xDFF1D6 reason:NCReason_Automatic]; [file setInlineComment:@"UHRES bit plane vertical stop" atVirtualAddress:0xDFF1D6 reason:CCReason_Automatic];
    [file setName:@"HHPOSW" forVirtualAddress:0xDFF1D8 reason:NCReason_Automatic]; [file setInlineComment:@"DUAL mode hires H beam counter write" atVirtualAddress:0xDFF1D8 reason:CCReason_Automatic];
    [file setName:@"HHPOSR" forVirtualAddress:0xDFF1DA reason:NCReason_Automatic]; [file setInlineComment:@"DUAL mode hires H beam counter read" atVirtualAddress:0xDFF1DA reason:CCReason_Automatic];
    [file setName:@"BEAMCON0" forVirtualAddress:0xDFF1DC reason:NCReason_Automatic]; [file setInlineComment:@"Beam counter control register (SHRES,UHRES,PAL)" atVirtualAddress:0xDFF1DC reason:CCReason_Automatic];
    [file setName:@"HSSTRT" forVirtualAddress:0xDFF1DE reason:NCReason_Automatic]; [file setInlineComment:@"Horizontal sync start (VARHSY)" atVirtualAddress:0xDFF1DE reason:CCReason_Automatic];
    [file setName:@"VSSTRT" forVirtualAddress:0xDFF1E0 reason:NCReason_Automatic]; [file setInlineComment:@"Vertical sync start (VARVSY)" atVirtualAddress:0xDFF1E0 reason:CCReason_Automatic];
    [file setName:@"HCENTER" forVirtualAddress:0xDFF1E2 reason:NCReason_Automatic]; [file setInlineComment:@"Horizontal position for Vsync on interlace" atVirtualAddress:0xDFF1E2 reason:CCReason_Automatic];
    [file setName:@"DIWHIGH" forVirtualAddress:0xDFF1E4 reason:NCReason_Automatic]; [file setInlineComment:@"Display window - upper bits for start/stop" atVirtualAddress:0xDFF1E4 reason:CCReason_Automatic];
    [file setName:@"BPLHMOD" forVirtualAddress:0xDFF1E6 reason:NCReason_Automatic]; [file setInlineComment:@"UHRES bit plane modulo" atVirtualAddress:0xDFF1E6 reason:CCReason_Automatic];
    [file setName:@"SPRHPTH" forVirtualAddress:0xDFF1E8 reason:NCReason_Automatic]; [file setInlineComment:@"UHRES sprite pointer (high 5 bits)" atVirtualAddress:0xDFF1E8 reason:CCReason_Automatic];
    [file setName:@"SPRHPTL" forVirtualAddress:0xDFF1EA reason:NCReason_Automatic]; [file setInlineComment:@"UHRES sprite pointer (low 15 bits)" atVirtualAddress:0xDFF1EA reason:CCReason_Automatic];
    [file setName:@"BPLHPTH" forVirtualAddress:0xDFF1EC reason:NCReason_Automatic]; [file setInlineComment:@"VRam (UHRES) bitplane pointer (hi 5 bits)" atVirtualAddress:0xDFF1EC reason:CCReason_Automatic];
    [file setName:@"BPLHPTL" forVirtualAddress:0xDFF1EE reason:NCReason_Automatic]; [file setInlineComment:@"VRam (UHRES) bitplane pointer (lo 15 bits)" atVirtualAddress:0xDFF1EE reason:CCReason_Automatic];
    [file setName:@"FMODE" forVirtualAddress:0xDFF1FC reason:NCReason_Automatic]; [file setInlineComment:@"mode register" atVirtualAddress:0xDFF1FC reason:CCReason_Automatic];

    
    return DIS_OK;
}

- (void)fixupRebasedFile:(NSObject<HPDisassembledFile> *)file
               withSlide:(int64_t)slide
        originalFileData:(nonnull const void *)fileBytes
                  length:(size_t)length
            originalPath:(nullable NSString *)fileFullPath {
    
}

- (FileLoaderLoadingStatus)loadDebugData:(const void *)fileBytes
                                  length:(size_t)fileLength
                            originalPath:(NSString *)fileFullPath
                                 forFile:(NSObject<HPDisassembledFile> *)file
                           usingCallback:(FileLoadingCallbackInfo)callback {
    return DIS_NotSupported;
}

- (NSData *)extractFromData:(const void *)fileBytes
                     length:(size_t)fileLength
      usingDetectedFileType:(NSObject<HPDetectedFileType> *)fileType
           originalFileName:(NSString *)filename
               originalPath:(NSString *)fileFullPath
         returnAdjustOffset:(uint64_t *)adjustOffset
       returnAdjustFilename:(NSString *__autoreleasing *)newFilename {
    return nil;
}

- (void)setupFile:(nonnull NSObject<HPDisassembledFile> *)file
afterExtractionOf:(nonnull NSString *)filename
     originalPath:(NSString *)fileFullPath
             type:(nonnull NSObject<HPDetectedFileType> *)fileType {

}

@end
