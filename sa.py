import pefile
import numpy as np
# import os

execs = [
"1F2EB7B090018D975E6D9B40868C94CA",
"33DE5067A433A6EC5C328067DC18EC37",
"65018CD542145A3792BA09985734C12A",
"650A6FCA433EE243391E4B4C11F09438",
"6FAA4740F99408D4D2DDDD0B09BBDEFD",
"785003A405BC7A4EBCBB21DDB757BF3F",
"8442AE37B91F279A9F06DE4C60B286A3",
"99A39866A657A10949FCB6D634BB30D5",
"A316D5AECA269CA865077E7FFF356E7D",
"AAAz2E1B6940985A23E5639450F8391820655",

"AL65_DB05DF0498B59B42A8E493CF3C10C578",
"B07322743778B5868475DBE66EEDAC4F",
"B98hX8E8622C393D7E832D39E620EAD5D3B49",
"BVJ2D9FBF759F527AF373E34673DC3ACA462",
"DS22_A670D13D4D014169C4080328B8FEB86",
"EEE99EC8AA67B05407C01094184C33D2B5A44",
"F6655E39465C2FF5B016980D918EA028",
"F8437E44748D2C3FCF84019766F4E6DC",
"FGJKJJ1_2BA0D0083976A5C1E3315413CDCFFCD2",
"FGTR43_EF8E0FB20E7228C7492CCDC59D87C690",

"FHHH6576C196385407B0F7F4B1B537D88983",
"FTTR9EA3C16194CE354C244C1B74C46CD92E",
"GBV66_8F259BB36E00D124963CFA9B86F502E",
"GFT4_7DDD3D72EAD03C7518F5D47650C8572",
"HJGQDD892986B2249B5214639ECC8AC0223",
"JH78C0A33A1B472A8C16123FD696A5CE5EBB",
"JKK8CA6FE7A1315AF5AFEAC2961460A80569",
"K99_C3A9A7B026BFE0E55FF219FD6AA7D94",
"KLp90_6D5C8FC4B14559F73B6136D85B94198",
"L11_1415EB8519D13328091CC5C76A624E3D",

"NBV_8B75BCBFF174C25A0161F30758509A44",
"NV99_C9C9DBF388A8D81D8CFB4D3FC05F8E4",
"PL98_BD8B082B7711BC980252F988BB0CA936",
"POL55_A4F1ECC4D25B33395196B5D51A06790",
"QW2_4C6BDDCCA2695D6202DF38708E14FC7E",
"RTC_7F85D7F628CE62D1D8F7B39D8940472",
"SAM_B659D71AE168E774FAAF38DB30F4A84",
"TG78Z__727A6800991EEAD454E53E8AF164A99C",
"VBMM9_149B7BD7218AAB4E257D28469FDDB0D",
"VC990_468FF2C12CFFC7E5B2FE0EE6BB3B239E",
]


prueba = {"correlativo": None, "nameExec": None, "sectionName": [], "sectionVA": [], 
			"sectionVS": [], "sectionSR": [], "kernel32": [], "msvcrt": [], "shell32": [], 
			"user32": [], "ws232": [], "ADVAPI32": [], "GDI32": [], "KERNEL32": [], 
			"NETAPI32": [], "PSAPI": [], "WININET": [], "ntdll": [], "TimeStamp": None}

# pe = pefile.PE("65018CD542145A3792BA09985734C12A")

# algo = [10, 20, 30, 40, 50]

granPrueba = []

entrysList = []

for a in execs:
	sectionNames = []
	sectionVA = []
	sectionVS = []
	sectionSR = []
	kernel32 = []
	msvcrt = []
	shell32 = []
	user32 = []
	ws232 = []
	ADVAPI32 = []
	GDI32 = []
	KERNEL32 = []
	NETAPI32 = []
	PSAPI = []
	WININET = []
	ntdll = []

	
	# print(execs.index(a) + 1)
	print("a")
	print(a)
	c = execs.index(a) + 1
	pe = pefile.PE(a)
	prueba["correlativo"] = c
	prueba["nameExec"] = a

	print(c)

	print("Secciones")
	for section in pe.sections:
	    print(section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData)
	    b = section.Name
	    sectionNames.append(b.decode('utf-8'))
	    sectionVA.append(section.VirtualAddress)
	    sectionVS.append(section.Misc_VirtualSize)
	    sectionSR.append(section.SizeOfRawData)

	prueba["sectionName"] = sectionNames
	prueba["sectionVA"] = sectionVA
	prueba["sectionVS"] = sectionVS
	prueba["sectionSR"] = sectionSR

	print()
	print()
	print("Entradas")
	for entry in pe.DIRECTORY_ENTRY_IMPORT:
		print('Llamadas DLL:')
		print (entry.dll)
		l = entry.dll
		print('Llamadas a funciones:')
		entrysList.append(str(l.decode('utf-8')))
		if str(entry.dll) == "b'KERNEL32.DLL'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				kernel32.append(x.decode('utf-8'))
			prueba["kernel32"] = kernel32


		elif str(entry.dll) == "b'ADVAPI32.dll'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				ADVAPI32.append(x.decode('utf-8'))
			prueba["ADVAPI32"] = ADVAPI32
		elif str(entry.dll) == "b'GDI32.dll'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				GDI32.append(x.decode('utf-8'))
			prueba["GDI32"] = GDI32
		elif str(entry.dll) == "b'KERNEL32.dll'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				KERNEL32.append(x.decode('utf-8'))
			prueba["KERNEL32"] = KERNEL32
		elif str(entry.dll) == "b'NETAPI32.dll'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				NETAPI32.append(x.decode('utf-8'))
			prueba["NETAPI32"] = NETAPI32
		elif str(entry.dll) == "b'PSAPI.DLL'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				PSAPI.append(x.decode('utf-8'))
			prueba["PSAPI"] = PSAPI
		elif str(entry.dll) == "b'WININET.dll'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				WININET.append(x.decode('utf-8'))
			prueba["WININET"] = WININET
		elif str(entry.dll) == "b'ntdll.dll'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				ntdll.append(x.decode('utf-8'))
			prueba["ntdll"] = ntdll
		
		elif str(entry.dll) == "b'MSVCRT.dll'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				msvcrt.append(x.decode('utf-8'))
			prueba["msvcrt"] = msvcrt
		elif str(entry.dll) == "b'SHELL32.dll'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				shell32.append(x.decode('utf-8'))
			prueba["shell32"] = shell32
		elif str(entry.dll) == "b'USER32.dll'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				user32.append(x.decode('utf-8'))
			prueba["user32"] = user32
		elif str(entry.dll) == "b'WS2_32.dll'":
			for function in entry.imports:
				x = function.name
				print('\t', x.decode('utf-8'))
				ws232.append(x.decode('utf-8'))
			prueba["ws232"] = ws232

	# listamalware = os.listdir(path)

	print()
	print()
	print("TimeStamp")
	print("TimeDateStamp : " + pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1])
	z = pe.FILE_HEADER.dump_dict()['TimeDateStamp']['Value'].split('[')[1][:-1]
	print(z)

	prueba["TimeStamp"] = z
	print(c)
	
	# print()
	# print()
	# print(pe.FILE_HEADER.NumberOfSections)

	granPrueba.append(prueba)

	prueba = {"correlativo": None, "nameExec": None, "sectionName": [], "sectionVA": [], 
			"sectionVS": [], "sectionSR": None, "kernel32": None, "msvcrt": None, "shell32": None, 
			"user32": None, "ws232": None, "TimeStamp": None}

# print(granPrueba)

import pandas as pd

df = pd.DataFrame(granPrueba)

print(df)

# print(entrysList)

def unique(list1):
	x = np.array(list1)
	print(np.unique(x))

unique(entrysList)

df.to_csv("dataset.csv")

