Educational implentation of AES described in FIPS PUB 197

This implementation is for purely educational purposes. It is not protected from side channel analysis attacks


Here is a sample execution of each step of AES encryption
```
key Block
2B	28	AB	09	
7E	AE	F7	CF	
15	D2	15	4F	
16	A6	88	3C	

Plain Text Block
6B	2E	E9	73	
C1	40	3D	93	
BE	9F	7E	17	
E2	96	11	2A	
Initial Rounded
40	06	42	7A	
BF	EE	CA	5C	
AB	4D	6B	58	
F4	30	99	16	

-----------------------------------
 Encrypt Round 1
Substituted
09	6F	2C	DA	
08	28	74	4A	
62	E3	7F	6A	
BF	04	EE	47	

Shifted
09	6F	2C	DA	
28	74	4A	08	
7F	6A	62	E3	
47	BF	04	EE	

Mixed
52	97	E0	BA	
9F	86	1A	1A	
16	15	AE	26	
C2	CA	54	59	

New Key Block KeySchedule
A0	88	23	2A	
FA	54	A3	6C	
FE	2C	39	76	
17	B1	39	05	

Rounded
F2	1F	C3	90	
65	D2	B9	76	
E8	39	97	50	
D5	7B	6D	5C	

-----------------------------------
 Encrypt Round 2
Substituted
89	C0	2E	60	
4D	B5	56	38	
9B	12	88	53	
03	21	3C	4A	

Shifted
89	C0	2E	60	
B5	56	38	4D	
88	53	9B	12	
4A	03	21	3C	

Mixed
0F	31	AE	39	
31	9A	C9	F0	
E9	35	58	4D	
29	58	93	87	

New Key Block KeySchedule
F2	7A	59	73	
C2	96	35	59	
95	B9	80	F6	
F2	43	7A	7F	

Rounded
FD	4B	F7	4A	
F3	0C	FC	A9	
7C	8C	D8	BB	
DB	1B	E9	F8	

-----------------------------------
 Encrypt Round 3
Substituted
54	B3	68	D6	
0D	FE	B0	D3	
10	64	61	EA	
B9	AF	1E	41	

Shifted
54	B3	68	D6	
FE	B0	D3	0D	
61	EA	10	64	
41	B9	AF	1E	

Mixed
91	E5	01	DA	
51	54	4A	7E	
AB	1C	71	31	
E1	FD	3E	34	

New Key Block KeySchedule
3D	47	1E	6D	
80	16	23	7A	
47	FE	7E	88	
7D	3E	44	3B	

Rounded
AC	A2	1F	B7	
D1	42	69	04	
EC	E2	0F	B9	
9C	C3	7A	0F	

-----------------------------------
 Encrypt Round 4
Substituted
91	3A	C0	A9	
3E	2C	F9	F2	
CE	98	76	56	
DE	2E	DA	76	

Shifted
91	3A	C0	A9	
2C	F9	F2	3E	
76	56	CE	98	
76	DE	2E	DA	

Mixed
4D	EC	76	49	
25	F7	58	BC	
CB	16	C7	C9	
1E	46	3B	E9	

New Key Block KeySchedule
EF	A8	B6	DB	
44	52	71	0B	
A5	5B	25	AD	
41	7F	3B	00	

Rounded
A2	44	C0	92	
61	A5	29	B7	
6E	4D	E2	64	
5F	39	00	E9	

-----------------------------------
 Encrypt Round 5
Substituted
3A	1B	BA	4F	
EF	06	A5	A9	
9F	E3	98	43	
CF	12	63	1E	

Shifted
3A	1B	BA	4F	
06	A5	A9	EF	
98	43	9F	E3	
1E	CF	12	63	

Mixed
F8	4E	02	34	
9B	40	5B	D7	
35	72	00	D8	
EC	4E	C7	1B	

New Key Block KeySchedule
D4	7C	CA	11	
D1	83	F2	F9	
C6	9D	B8	15	
F8	87	BC	BC	

Rounded
2C	32	C8	25	
4A	C3	A9	2E	
F3	EF	B8	CD	
14	C9	7B	A7	

-----------------------------------
 Encrypt Round 6
Substituted
71	23	E8	3F	
D6	2E	D3	31	
0D	DF	6C	BD	
FA	DD	21	5C	

Shifted
71	23	E8	3F	
2E	D3	31	D6	
6C	BD	0D	DF	
5C	FA	DD	21	

Mixed
A0	6F	48	E1	
C5	B8	40	D3	
63	84	BF	2F	
69	E4	BE	0A	

New Key Block KeySchedule
6D	11	DB	CA	
88	0B	F9	00	
A3	3E	86	93	
7A	FD	41	FD	

Rounded
CD	7E	93	2B	
4D	B3	B9	D3	
C0	BA	39	BC	
13	19	FF	F7	

-----------------------------------
 Encrypt Round 7
Substituted
BD	F3	DC	F1	
E3	6D	56	66	
BA	F4	12	65	
7D	D4	16	68	

Shifted
BD	F3	DC	F1	
6D	56	66	E3	
12	65	BA	F4	
68	7D	D4	16	

Mixed
AC	1F	67	25	
39	8D	11	3D	
4C	E8	B2	DB	
73	C7	10	33	

New Key Block KeySchedule
4E	5F	84	4E	
54	5F	A6	A6	
F7	C9	4F	DC	
0E	F3	B2	4F	

Rounded
E2	40	E3	6B	
6D	D2	B7	9B	
BB	21	FD	07	
7D	34	A2	7C	

-----------------------------------
 Encrypt Round 8
Substituted
98	09	11	7F	
3C	B5	A9	14	
EA	FD	54	C5	
FF	18	3A	10	

Shifted
98	09	11	7F	
B5	A9	14	3C	
54	C5	EA	FD	
10	FF	18	3A	

Mixed
AB	C8	EC	7D	
05	EB	04	21	
B5	2B	E2	EC	
72	92	FD	34	

New Key Block KeySchedule
EA	B5	31	7F	
D2	8D	2B	8D	
73	BA	F5	29	
21	D2	60	2F	

Rounded
41	7D	DD	02	
D7	66	2F	AC	
C6	91	17	C5	
53	40	9D	1B	

-----------------------------------
 Encrypt Round 9
Substituted
83	FF	C1	77	
0E	33	15	91	
B4	81	F0	A6	
ED	09	5E	AF	

Shifted
83	FF	C1	77	
33	15	91	0E	
F0	A6	B4	81	
AF	ED	09	5E	

Mixed
17	91	8C	23	
41	C9	36	AD	
A1	91	38	82	
18	68	6F	AA	

New Key Block KeySchedule
AC	19	28	57	
77	FA	D1	5C	
66	DC	29	00	
F3	21	41	6E	

Rounded
BB	88	A4	74	
36	33	E7	F1	
C7	4D	11	82	
EB	49	2E	C4	

-----------------------------------
Last Substituted
EA	C4	49	92	
05	C3	94	A1	
C6	E3	82	13	
E9	3B	31	1C	

Shifted
EA	C4	49	92	
C3	94	A1	05	
82	13	C6	E3	
1C	E9	3B	31	

New Key Block KeySchedule
D0	C9	E1	B6	
14	EE	3F	63	
F9	25	0C	0C	
A8	89	C8	A6	

Final Ciphertext output
3A	0D	A8	24	
D7	7A	9E	66	
7B	36	CA	EF	
B4	60	F3	97	

Encrypted Text Block
3A	0D	A8	24	
D7	7A	9E	66	
7B	36	CA	EF	
B4	60	F3	97	
```
