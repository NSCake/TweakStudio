//
//  ida-psc-cleaner.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-06-11
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

function CleanIDAPseudocode(code: string): string {
    return code
        .replace(/CFSTR\((".*")\)/g, '@$1') // NSString literals
        .replace(/= \((.+)\)(?!;)/g, '= ') // Assignment casts
        .replace(/\((?:unsigned )?(?:void|char|__int64)( \*)?\)([^\s])/g, '$2') // Other casts
        .replace(/&OBJC_CLASS___(\w+)/g, '$1') // Class-refs to class names
        .replace(/objc_msgSend\((\w+), "([\w:]+)"\)/g, '[$1 $2]') // 0 arg method calls
        .replace(/objc_msgSend\((\w+), "([\w:]+)", (.+)\)/g, '[$1 $2]($3)') // 1+ arg method calls
        .replace(/(?:\(\w+ \*\))?objc_retainAutoreleasedReturnValue\((.+)\)/g, '[$1 retain]') // Retain
        .replace(/objc_retain\((@".*)\)/g, '$1') // Retaining constant strings
        .replace(/(\w+) = objc_retainAutorelease\((\w+)\)/g, '$1 = $2') // Autorelease
        .replace(/objc_release\((\w+)\)/g, '[$1 release]') // Release
        .replace(/(\s+)(\w+) = (.+);\s+(\w+) = \[\2 retain\];/g, '$1$2 = $4 = $3;') // Variable weirdness
        .replace(/return objc_storeStrong\(&(\w+), 0LL\)/g, 'return 0') // return 0
        .replace(/\n\s+objc_storeStrong\(&(\w+), 0LL\);/g, '') // Remove `x = nil;`
        .replace(/objc_storeStrong\(&(\w+), (\w+)\)/g, '$1 = $2') // x = y
        .replace(/ & 1/g, '') // if ( x & 1 ) -> if ( x )
        .replace(/\[(\w+) (objectAtIndexedSubscript:)\]\((.+)\);/g, '$1[$3]; // $2') // Subscripting
        // disabled bc VS Code auto-detects 2 spaces first and this doesn't change it
        // .replace(/  /g, '    ') // 4 spaces
}

export default CleanIDAPseudocode;
