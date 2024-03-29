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

#import "CommonTypes.h"

@protocol HPDetectedFileType

/// Internal information for the loader. You can put any value you need here.
@property (assign)           NSUInteger internalId;
@property (nullable, strong) id internalObject;

@property (nullable, strong) NSString *shortDescriptionString;    /// This string can be used by the command line tool to select the loader.

@property (assign)           BOOL compositeFile;                  /// The loader handles only a container (like a static library, a ZIP file...) and will delegate the loading process of the contained file to another loader.

@property (nullable, copy)   NSString *fileDescription;

@property (assign)           BOOL debugData;                      /// set to YES if this is debug data, like a dSYM file for instance.
@property (assign)           DFTAddressWidth addressWidth;
@property (nullable, copy)   NSString *cpuFamily;                 /// Generic CPU family name to discriminate CPU modules. Names may be "intel", "arm", "aarch64" or any other kind.
@property (nullable, copy)   NSString *cpuSubFamily;              /// Modes could be "x86" or "x86_64" for the "intel" family, or "v6", "v7", "v7s", "v7m" for the "nullable, arm" family.

@property (nullable, strong) NSArray *additionalParameters;       /// An array of NSObject<HPLoaderOptionComponents> that describes some additional parameters to present to the user when using this loader.

@property (assign)           DFTPriority priority;                /// Used to modify the order of the loaders in the dialog

@end
