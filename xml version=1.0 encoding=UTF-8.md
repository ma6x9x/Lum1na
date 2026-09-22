<?xml version="1.0" encoding="UTF-8"?>  
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">  
<plist version="1.0">  
<dict>  
    <!-- Game Center (keep if needed) -->  
    <key>com.apple.developer.game-center</key>  
    <true/>  
      
    <!-- File Access -->  
    <key>com.apple.security.exception.files.absolute-path.read-write</key>  
    <array>  
        <string>/</string>  
        <string>/var/</string>  
        <string>/var/mobile/</string>  
        <string>/var/mobile/Documents/</string>  
        <string>/var/tmp/</string>  
        <string>/private/</string>  
        <string>/private/var/</string>  
    </array>  
      
    <!-- IOKit User Clients - CRITICAL for exploits -->  
    <key>com.apple.security.exception.iokit-user-client-class</key>  
    <array>  
        <string>IOGPUDevice</string>  
        <string>IOSurfaceRootUserClient</string>  
        <string>AppleAVE2UserClient</string>  
        <string>AppleKeyStore</string>  
        <string>AppleKeyStoreUserClient</string>  
        <string>AppleSEPKeyStore</string>  
        <string>AppleSEPKeyStoreUserClient</string>  
        <string>IOUserClient</string>  
        <string>IOUserClientClass</string>  
    </array>  
      
    <!-- Task ports for kernel access -->  
    <key>com.apple.system-task-ports</key>  
    <true/>  
      
    <!-- Get task allow for debugging/exploitation -->  
    <key>get-task-allow</key>  
    <true/>  
      
    <!-- Keychain access -->  
    <key>keychain-access-groups</key>  
    <array>  
        <string>$(AppIdentifierPrefix)com.research.lum1na</string>  
    </array>  
      
    <!-- Platform application (no sandbox) -->  
    <key>platform-application</key>  
    <true/>  
      
    <!-- Task for PID (process access) -->  
    <key>task_for_pid-allow</key>  
    <true/>  
      
    <!-- Additional entitlements for jailbreak -->  
    <key>com.apple.private.security.no-sandbox</key>  
    <true/>  
      
    <key>com.apple.private.security.no-container</key>  
    <true/>  
      
    <key>com.apple.private.kernel.override-codesigning</key>  
    <true/>  
      
    <key>com.apple.private.kernel.allow-obsolete-hv</key>  
    <true/>  
      
    <key>com.apple.private.iokit.IOServiceSetAuthorizationID</key>  
    <true/>  
</dict>  
</plist>  
