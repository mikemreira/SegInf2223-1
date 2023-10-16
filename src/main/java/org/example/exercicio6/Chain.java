package org.example.exercicio6;

import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Objects;
import java.util.Scanner;
import java.util.concurrent.atomic.AtomicInteger;

import static java.lang.Float.parseFloat;
import static java.lang.Integer.parseInt;

public class Chain {
    private static ArrayList<Block> getChain(String filename) throws IOException {
        ArrayList<Block> chain = new ArrayList<>();
        FileReader reader = new FileReader(filename);
        BufferedReader buffer = new BufferedReader(reader);
        String line = buffer.readLine();
        if (line == null) {
            Transaction t = new Transaction(-1, -1, 1.0f);
            chain.add(new Block(t, "0"));
            return chain;
        }
        while (line != null) {
            String[] stringSplit = line.split(",");
            int origin = parseInt(stringSplit[0]);
            int destination = parseInt(stringSplit[1]);
            float value = parseFloat(stringSplit[2]);
            String hash = stringSplit[3];

            Transaction t = new Transaction(origin, destination, value);
            Block b = new Block(t, hash);
            chain.add(b);
            line = buffer.readLine();
        }
        buffer.close();
        return chain;
    }

    public static void verifyChain(String filename) throws NoSuchAlgorithmException, IOException {
        ArrayList<Block> chain = getChain(filename);
        for (int i = 1; i < chain.size(); i++) {
            if (!Objects.equals(chain.get(i).hash, buildHash(chain.get(i - 1)))) {
                System.out.println("Chain verification has failed.");
                return;
            }
        }
        System.out.println("Chain verification succeeded: ");
        AtomicInteger idx = new AtomicInteger();
        chain.forEach(block -> System.out.println(idx.getAndIncrement() + " - " + block.hash));
    }

    public static String buildHash(Block block) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-256");
        md.update(block.toString().getBytes());
        StringBuilder builder = new StringBuilder();
        for (byte b : md.digest()) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }

    public static void addBlock(int origin, int destination, float value, String filename) throws IOException, NoSuchAlgorithmException {
        Transaction t = new Transaction(origin, destination, value);
        ArrayList<Block> chain = getChain(filename);
        FileOutputStream stream = new FileOutputStream(filename);
        chain.add(new Block(t, buildHash(chain.get(chain.size() - 1))));
        chain.forEach(it -> {
            try {
                stream.write((it.toString() + "\n").getBytes());
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        stream.close();
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
        for (;;) {
            System.out.print("$ ");
            Scanner key = new Scanner(System.in);
            String[] str = key.nextLine().split(" ");
            switch (str[0]) {
                case "addblock" -> {
                    if (str.length != 5) {
                        System.out.println("Expected 5 arguments, but received " + str.length);
                        break;
                    }
                    addBlock(parseInt(str[1]), parseInt(str[2]), Float.parseFloat(str[3]), str[4]);
                }
                case "verifychain" -> {
                    if (str.length != 2) {
                        System.out.println("Expected 2 arguments, but input was " + str.length);
                        break;
                    }
                    verifyChain(str[1]);
                }
                case "quit" -> {
                    return;
                }
            }
        }
    }
}
