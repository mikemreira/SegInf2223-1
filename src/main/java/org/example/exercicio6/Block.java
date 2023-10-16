package org.example.exercicio6;

public class Block {
    public Transaction transaction;
    public String hash;
    public Block(Transaction transaction, String hash) {
        this.transaction = transaction;
        this.hash = hash;
    }

    @Override
    public String toString() {
        return transaction.origin + "," + transaction.destination + "," + transaction.operation + "," + hash;
    }
}
