#!/bin/bash

for i in 01 02 03 04 05 06 07 08 09 10 11 12 13 14 15 16 17 18 19 20
do
	echo "java -cp pad_oracle.jar:bcprov-jdk15-130.jar: p2_S_20170715 < ../ciphertexts/ciphertext_$i.txt"
	java -cp pad_oracle.jar:bcprov-jdk15-130.jar: p2_S_20170715 < ../ciphertexts/ciphertext_$i.txt
done
