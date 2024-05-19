package TermProject;

import java.io.*;
import java.security.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;

public class Code {
    private static final int maxPasswordPerFile = 10000;
    private static Map<Character, Integer> fileCounters = new HashMap<>();
    private static Map<Character, Integer> fileCapacities = new HashMap<>();
    private static Map<Character, Set<String>> uniquePasswords = new HashMap<>();

    public static void main(String[] args) {
        String unprocessedFolder = "Unprocessed-Passwords";
        String processedFolder = "Processed";
        String indexFolder = "Index";

        createFolderIfNotExists(processedFolder);
        createFolderIfNotExists(indexFolder);
        
        Scanner sc = new Scanner(System.in);

        while (true) {
            System.out.println("\nSeçenekler:");
            System.out.println("1. Index işlemini gerçekleştir");
            System.out.println("2. Rastgele seçilen 10 şifreyi ara");
            System.out.println("3. Aramak için şifre gir");
            System.out.println("4. Çıkış yap");
            System.out.print("Seçiminizi yapın (1-4): ");

            int choice = sc.nextInt();
            sc.nextLine(); 
            switch (choice) {
                case 1:
                	processFolder(unprocessedFolder, indexFolder);
                    break;
                case 2:
                    measureSearchPerformance(indexFolder);
                    break;
                case 3:
                    System.out.print("\nAramak istediğiniz parolayı girin: ");
                    String queryPassword = sc.nextLine();
                    searchPassword(queryPassword, indexFolder);
                    break;
                case 4:
                    System.out.println("Programdan çıkılıyor...");
                    sc.close();
                    return;
                default:
                    System.out.println("Lütfen tekrar deneyin.");
            }
        }
    }

    private static void createFolderIfNotExists(String folderName) {
        File dir = new File(folderName);
        if (!dir.exists()) {
            if (dir.mkdir()) {
                System.out.println(folderName + " klasörü oluşturuldu.");
            } else {
                System.out.println(folderName + " klasörü oluşturulamadı.");
            }
        } else {
            System.out.println(folderName + " klasörü zaten mevcut.");
        }
    }

    private static void processFolder(String sourceF, String indexF) {
        File sourceFolder = new File(sourceF);
        File[] listOfFiles = sourceFolder.listFiles();

        if (listOfFiles != null) {
            for (File file : listOfFiles) {
                if (file.isFile()) {
                	processPasswordFile(file, indexF);
                    moveFileToProcessed(file, "Processed");
                }
            }
        } else {
            System.out.println("Unprocessed-Passwords klasöründe dosya bulunamadı.");
        }
    }

    private static void processPasswordFile(File file, String indexF) {
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty()) {
                    char firstChar = Character.toLowerCase(line.charAt(0));
                    if (!uniquePasswords.containsKey(firstChar)) {
                        uniquePasswords.put(firstChar, new HashSet<>());
                    }
                    if (uniquePasswords.get(firstChar).add(line)) {
                        savePassword(line, firstChar, indexF, file.getName());
                    }
                }
            }
        } catch (IOException e) {
            System.out.println(file.getName() + " dosyası işlenirken hata oluştu: " + e.getMessage());
        }
    }

    private static void savePassword(String password, char firstChar, String indexF, String sourceFileName) {
        try {
            String md5Hash = hashPassword(password, "MD5");
            String sha1Hash = hashPassword(password, "SHA-1");
            String sha256Hash = hashPassword(password, "SHA-256");
            String output = password + "|" + md5Hash + "|" + sha1Hash + "|" + sha256Hash + "|" + sourceFileName;

            if (!Character.isLetterOrDigit(firstChar) && !Character.isWhitespace(firstChar)) {
                firstChar = '_';
            }

            if (!fileCounters.containsKey(firstChar)) {
                fileCounters.put(firstChar, 0);
                fileCapacities.put(firstChar, 0);
            }

            if (fileCapacities.get(firstChar) >= maxPasswordPerFile) {
                fileCounters.put(firstChar, fileCounters.get(firstChar) + 1);
                fileCapacities.put(firstChar, 0);
            }

            int fileIndex = fileCounters.get(firstChar);
            String fileName = indexF + "/" + firstChar + "_" + fileIndex + ".txt";
            fileCapacities.put(firstChar, fileCapacities.get(firstChar) + 1);

            try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName, true))) {
                writer.write(output);
                writer.newLine();
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            System.out.println(password + " parolası kaydedilirken hata oluştu: " + e.getMessage());
        }
    }

    private static String hashPassword(String password, String algorithm) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(algorithm);
        byte[] hashBytes = md.digest(password.getBytes());
        StringBuilder sb = new StringBuilder();
        for (byte b : hashBytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private static void moveFileToProcessed(File file, String processedF) {
        try {
            Files.move(file.toPath(), Path.of(processedF, file.getName()), StandardCopyOption.REPLACE_EXISTING);
            System.out.println(file.getName() + " dosyası " + processedF+ " klasörüne taşındı.");
                } catch (IOException e) {
                    System.out.println(file.getName() + " dosyası taşınamadı. Hata: " + e.getMessage());
                }
            }

            private static void searchPassword(String password, String indexF) {
                char firstChar = Character.toLowerCase(password.charAt(0));
                File[] indexFiles = new File(indexF).listFiles((dir, name) -> name.startsWith(String.valueOf(firstChar)));

                if (indexFiles != null) {
                    boolean found = false;
                    for (File file : indexFiles) {
                        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                            String line;
                            while ((line = reader.readLine()) != null) {
                                if (line.startsWith(password + "|")) {
                                    System.out.println("Parola bulundu: " + line);
                                    found = true;
                                    break;
                                }
                            }
                        } catch (IOException e) {
                            System.out.println(file.getName() + " dosyası okunurken hata oluştu: " + e.getMessage());
                        }
                        if (found) {
                            break;
                        }
                    }

                    if (!found) {
                        try {
                            String md5Hash = hashPassword(password, "MD5");
                            String sha1Hash = hashPassword(password, "SHA-1");
                            String sha256Hash = hashPassword(password, "SHA-256");
                            String output = password + "|" + md5Hash + "|" + sha1Hash + "|" + sha256Hash + "|search";

                            if (!fileCounters.containsKey(firstChar)) {
                                fileCounters.put(firstChar, 0);
                                fileCapacities.put(firstChar, 0);
                            }

                            if (fileCapacities.get(firstChar) >= maxPasswordPerFile) {
                                fileCounters.put(firstChar, fileCounters.get(firstChar) + 1);
                                fileCapacities.put(firstChar, 0);
                            }

                            int fileIndex = fileCounters.get(firstChar);
                            String fileName = indexF + "/" + firstChar + "_" + fileIndex + ".txt";
                            fileCapacities.put(firstChar, fileCapacities.get(firstChar) + 1);

                            try (BufferedWriter writer = new BufferedWriter(new FileWriter(fileName, true))) {
                                writer.write(output);
                                writer.newLine();
                            }
                            System.out.println("Parola bulunamadı, eklendi: " + output);
                        } catch (IOException | NoSuchAlgorithmException e) {
                            System.out.println(password + " parolası kaydedilirken hata oluştu: " + e.getMessage());
                        }
                    }
                } else {
                    System.out.println("İlgili index dosyaları bulunamadı.");
                }
            }

            private static void measureSearchPerformance(String indexF) {
                Random random = new Random();
                String[] testPasswords = new String[10];
                for (int i = 0; i < 10; i++) {
                    testPasswords[i] = generateRandomPassword(random);
                }

                long totalTime = 0;
                for (String testPassword : testPasswords) {
                    long startTime = System.nanoTime();
                    searchPassword(testPassword, indexF);
                    long endTime = System.nanoTime();
                    totalTime += (endTime - startTime);
                }

                double averageTime = totalTime / 10.0 / 1_000_000.0; 
                System.out.println("Ortalama arama süresi: " + averageTime + " ms");
            }

            private static String generateRandomPassword(Random random) {
                String characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                int length = random.nextInt(6) + 4;
                StringBuilder password = new StringBuilder(length);
                for (int i = 0; i < length; i++) {
                    char randomChar = characters.charAt(random.nextInt(characters.length()));
                    password.append(randomChar);
                }
                return password.toString();
            }
        }

