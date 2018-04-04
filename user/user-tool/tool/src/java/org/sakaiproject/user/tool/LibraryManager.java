package org.sakaiproject.user.tool;

import java.lang.reflect.Field;

public final class LibraryManager {

    // ===========================================================
    // Private static fields
    // ===========================================================

    private static final String WIN32_X86 = "Win32_x86";
    private static final String WIN64_X64 = "Win64_x64";
    private static final String LINUX_X86 = "Linux_x86";
    private static final String LINUX_X86_64 = "Linux_x86_64";
    private static final String MAC_OS = "/Library/Frameworks/";

    // ===========================================================
    // Public static methods
    // ===========================================================

    public static void initLibraryPath() {
        String libraryPath = "D:\\disertatie\\Neurotec_Biometric_10_0_SDK_Trial\\Bin\\Win32_x86";//getLibraryPath();
        String jnaLibraryPath = System.getProperty("jna.library.path");
        if (jnaLibraryPath == null || "".equals(jnaLibraryPath)) {
            System.setProperty("jna.library.path", libraryPath.toString());
        } else {
            System.setProperty("jna.library.path", String.format("%s%s%s", jnaLibraryPath, System.getProperty("path.separator"), libraryPath.toString()));
        }
        System.setProperty("java.library.path",String.format("%s%s%s", System.getProperty("java.library.path"), System.getProperty("path.separator"), libraryPath.toString()));
        try {
            Field fieldSysPath = ClassLoader.class.getDeclaredField("sys_paths");
            fieldSysPath.setAccessible(true);
            fieldSysPath.set(null, null);
        } catch (SecurityException e) {
            System.out.println(e.getMessage());
        } catch (NoSuchFieldException e) {
            System.out.println(e.getMessage());
        } catch (IllegalArgumentException e) {
            System.out.println(e.getMessage());
        } catch (IllegalAccessException e) {
            System.out.println(e.getMessage());
        }
    }
}

