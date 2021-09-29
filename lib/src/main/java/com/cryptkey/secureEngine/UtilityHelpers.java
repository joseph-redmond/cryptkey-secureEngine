package com.cryptkey.secureEngine;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
public class UtilityHelpers {
    
    public static void writeToFile(String path, byte[] data){
        try{
            FileOutputStream output = new FileOutputStream(path);
            output.write(data);
            output.flush();
            output.close();
        }
        catch(Exception e){
            System.err.println("File encryption failed");
        }
    }
    public static void clearScreen() {  
        System.out.print("\033[H\033[2J");  
        System.out.flush();  
    }
    public static void printHelpScreen(){
        System.out.println("(-a, --algorithm) - algorithm used to encrypt/decrypt eg.(gcm)");
        System.out.println("(-o, --operation) - operation to apply to the file eg.(encrypt/decrypt)");
        System.out.println("(-p, --password) - password to encrypt/decrypt file without this it will encrypt without password");
        System.out.println("(files/dir) - add the directories and files to the end of the command");
        System.out.println("ex. java -jar cryptie.jar -a gcm -o encrypt -p password file1/dir1 file2/dir2 file3/dir3");
    }  

    public static String pathWithoutExtension(String path){
        int index = path.indexOf(".");
        return path.substring(0, index);
    }


    public static List<File> getFilesFromDirectories(File[] files, List<File> returnFiles){
        
        for(final File file : files){
            if(file.isDirectory()){
                getFilesFromDirectories(file.listFiles(), returnFiles);
            }
            else{
                returnFiles.add(file);      
            }
        }
        return returnFiles;
    }

    public static String createZipFile(List<File> files, String path){
        try{
        ZipOutputStream zipOutput = new ZipOutputStream(new FileOutputStream(path + ".zip"));
        for(File file : files){
            pathUpToSelectedParent(file.getAbsolutePath(), path);
            FileInputStream fileInput = new FileInputStream(file.getAbsolutePath());
            ZipEntry entry = new ZipEntry(pathUpToSelectedParent(file.getAbsolutePath(), path));
            zipOutput.putNextEntry(entry);
            byte[] data = fileInput.readAllBytes();
            zipOutput.write(data, 0, data.length);
            zipOutput.closeEntry();
        }
        zipOutput.close();
        System.out.println("Zip Finished");
        
    }
    catch(Exception e){
        System.err.println(e.getMessage());
    }
    return path + ".zip";
}

public static void unzipFile(File zipFile) throws IOException{
    File destDir = new File(zipFile.getAbsolutePath().substring(0, zipFile.getAbsolutePath().length() - zipFile.getName().length()));
    byte[] buffer = new byte[1024];
    ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile.getAbsolutePath()));
    ZipEntry zipEntry = zis.getNextEntry();
    while(zipEntry != null){
        File newFile = newFile(destDir, zipEntry);
        if(zipEntry.isDirectory()){
            if(!newFile.isDirectory() && !newFile.mkdirs()){
                throw new IOException("Failed to create directory " + newFile);
            }
        }
        else{
            File parent = newFile.getParentFile();
            if(!parent.isDirectory() && !parent.mkdirs()){
                throw new IOException("Failed to create directory " + parent);
            }

            FileOutputStream fos = new FileOutputStream(newFile);
            int len;
            while((len = zis.read(buffer)) > 0){
                fos.write(buffer, 0, len);
            }
            fos.close();       
        }
        zipEntry = zis.getNextEntry();
    }
    zis.closeEntry();
    zis.close();
    zipFile.delete();
}

public static File newFile(File destinationDir, ZipEntry zipeEntry) throws IOException{
    File destFile = new File(destinationDir, zipeEntry.getName());

    String destDirPath = destinationDir.getCanonicalPath();
    String destFilePath = destFile.getCanonicalPath();

    if(!destFilePath.startsWith(destDirPath + File.separator)){
        throw new IOException("Entry is outside of the target dir: " + zipeEntry.getName());
    }
    return destFile;
}


    public static String pathUpToSelectedParent(String filePath, String parentPath){
        return filePath.substring(filePath.indexOf(parentPath) + parentPath.length(), filePath.length());
    }
   
}