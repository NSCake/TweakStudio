//
//  ida-psc-cleaner.ts
//  Tweak Studio
//  
//  Created by Tanner Bennett on 2021-06-11
//  Copyright © 2021 Tanner Bennett. All rights reserved.
//

function CleanIDAPseudocode(code: string): string {
    return code
        .replace(/&OBJC_CLASS___(\w+)/g, '$1') // Class-refs to class names
        .replace(/objc_msgSend\((\w+), "([\w:]+)"\)/g, '[$1 $2]') // 0 arg method calls
        .replace(/objc_msgSend\((\w+), "([\w:]+)", (.+)\)/g, '[$1 $2]($3)') // 1+ arg method calls
        .replace(/(?:\(\w+ \*\))?objc_retainAutoreleasedReturnValue\((.+)\)/g, '[$1 retain]') // Retain
        .replace(/\n\s+objc_retainAutorelease.+/g, '') // Autorelease
        .replace(/objc_release\((\w+)\);/g, '[$1 release]') // Release
        .replace(/CFSTR\((".*")\)/g, '@$1') // NSString literals
        .replace(/\((?:unsigned )\w+( \*)?\)([^\s])/g, '$2') // Casts
}

export default CleanIDAPseudocode;
