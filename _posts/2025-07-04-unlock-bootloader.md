---
title: "Unlocking the Bootloader of Pixel 2 XL (Carrier Locked)"
categories: [Android, bootloader]
tags: [bootloader, rooting]
---
Unlocking the bootloader of a smartphone is a crucial step for users who want to take complete control of their devices. Whether you're interested in installing a custom ROM, rooting your phone, or simply exploring more advanced development features, unlocking the bootloader opens up these possibilities. However, on certain devices come with carrier locked. When you go in `Settings -> Developer Options -> OEM Unlocking`, you can see "**Connect to the internet or contact your carrier**".

Verizon, like many carriers, locks the bootloader on their devices to prevent users from modifying the software. This is primarily for security reasons, but it also limits customization.

In this guide, I will walk you through the process of unlocking the bootloader on a Verizon Pixel 2 XL. This will involve some preparation, and while the process isn't officially supported, many users have successfully done it with the right tools and knowledge. Please note that unlocking the bootloader will void your warranty and could expose your device to additional risks, so proceed with caution.

### Disclaimer:

Unlocking the bootloader voids the warranty and may affect the device's security.

### Prerequisites


1.  Pixel 2 XL (Verizon model)
2.  ADB and Fastboot Installed
3.  Enable Developer Options To unlock the bootloader, you first need to enable Developer Options on your Pixel 2 XL:
	- Go to Settings > About phone.
	- Scroll down to Build number and tap it 7 times until you see a
    message saying "You are now a developer."
4.  USB debugging enabled. Once Developer Options are enabled, go to
    Settings > Developer options and enable USB debugging. This allows
    your computer to send commands to your phone.
5.  Backup Your Data Unlocking the bootloader will wipe all data from
    your device, so it's important to back up all personal data.

![OEM Locked](/assets/img/01.png)

To check if your carrier is Verizon, you can use websites like IMEI.info or IMEI.org allow you to enter your device's IMEI number to check its carrier status.

### Device Information

I am using a Pixel 2 XL with the codename **Taimen**, running **Android 11** with the **2020-10-05** Security Patch.

## Steps to Unlock the Bootloader on the Pixel 2 XL (Verizon Carrier)

Please ensure that there is no SIM card inserted in the target device. 
Go to the Settings app on your device.

**Factory Reset via Settings**

-   Go to the Settings on your device.
-   Scroll down and tap on System.
-   Select Reset options.
-   Tap on Erase all data (factory reset).

![Reset Options 1](/assets/img/02.png)
![Reset Options 2](/assets/img/03.png)
![Reset Options 3](/assets/img/04.png)

Once the phone boots, disable "Use location", "Send usage and diagnostic data" in Google Services. Again enable Developer Options and USB Debugging after the phone starts and use the following command

```bash
adb shell pm uninstall --user 0 com.android.phone
```

The `pm` command is the Package Manager on Android. The uninstall `--user 0` flag is used to uninstall or disable the app for the primary
user (user 0). It doesn't remove the app completely from the system but disables it for that specific user.

On certain carrier-locked devices (especially Verizon models), the Phone app may have control over certain carrier-specific settings, including
restricting access to the OEM Unlocking option. By disabling or uninstalling the Phone app using this command, the device is no longer able to communicate with the carrier to enforce these restrictions.

Disabling the Phone app might not work in every case, as some devices have deeper carrier-level restrictions that can't be bypassed simply by
uninstalling the app.

Now if you go in the developer option you can see "Connect to the internet or contact your carrier" doesn't exist any more. ![OEM unlock
display](/assets/img/05.png)

Enable the OEM unlocking Option. Once that is done you can unlock the bootloader. Reboot the phone. You can use the following command to
reboot to bootloader.

```bash
adb reboot bootloader
```
You can see something like this: ![Fastboot
Mode](https://storage.googleapis.com/support-forums-api/attachment/thread-50687342-2661705676478564024.jpeg)

Image Source:
[google](https://support.google.com/pixelphone/thread/50687342/google-pixel-2xl-startet-nicht-bleibt-beim-booten-h%C3%A4ngen?hl=de)

Use the following command:


```bash
fastboot flashing unlock
```

![Bootloader Unlock Yes
No](https://fdn.gsmarena.com/imgroot/news/17/12/verizon-pixel2-bootloader-unlocking/inline/gsmarena_002.jpg)

Image Source:
[gsmarena](https://www.gsmarena.com/verizon_google_pixel_2_bootloaders_can_be_easily_unlocked-news-28920.php)

Once you enter the above command, your phone should ask if you're sure you'd like to unlock the bootloader. Use the volume keys to highlight
the "UNLOCK THE BOOTLOADER" option, then press the power button to select it.

After this reboot the phone

```bash
fastboot reboot
```


Now you can see warning that bootloader is unlocked. ![Bootloader Unlocked](https://www.androidauthority.com/wp-content/uploads/2018/10/Pixel-3-bootloader-unlocked-840w-472h.jpg.webp)

Image Source:
[androidauthority](https://www.androidauthority.com/unlock-pixel-3-bootloader-915961)

After setting up the device, you can navigate in the Developer Options and in that you can see: ![OEM unlocked](/assets/img/06.png)

### Conclusion

In this guide, we've walked through the steps to unlock the bootloader of your Carrier Locked (Verizon) Pixel 2 XL. If you've successfully 
unlocked your bootloader, feel free to share your experience. Thank you for reading, and good luck with your unlocked Pixel 2 XL!

### References

[How to unlock bootloader on Verizon Google Pixel XL (XDA)](https://www.xda-developers.com/how-to-unlock-bootloader-verizon-google-pixel-xl-running-android-10/)
