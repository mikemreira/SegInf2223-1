package org.example.exercicio6;

public class Transaction {
    public int origin;
    public int destination;
    public float operation;

    public Transaction(int origin, int destination, float operation) {
        this.origin = origin;
        this.destination = destination;
        this.operation = operation;
    }
}
