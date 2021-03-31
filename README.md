uses libkirk by Draan with bugfixes

ipl_ms.bin is a modified version of [MS_NORMAL](https://github.com/mathieulh/PSP_IPL_SDK/tree/master/MS_NORMAL) by Mathieulh linked to 0xBFC00020.

ipl.bin is premade ipl based on ipl_ms.bin containing the exploit

build: `gcc libkirk/*.c encrypt.c -o encrypt`
