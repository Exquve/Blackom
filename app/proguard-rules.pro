-keepclasseswithmembernames class * {
    native <methods>;
}

-keep class com.blackom.tunnel.vpn.TunnelVpnService { *; }

-keep class * extends androidx.room3.RoomDatabase
-keep @androidx.room3.Entity class *
-dontwarn androidx.room3.**

-keepclassmembers class kotlinx.coroutines.** {
    volatile <fields>;
}
-dontwarn kotlinx.coroutines.**
