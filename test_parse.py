import sys
import struct
import binascii

SECTOR_SIZE = 512

def pprint(data, count):
	tmp_str = ""
	for i in xrange(0, count):
			tmp_str	+= "%02x " % ord(data[i])
	print tmp_str	

def processFile(fileName):
	try:
		fd = open(fileName, "rb")
	except IOError:
		error = sys.exec_info()[1]
		sys.stderr.write("%s" % str(error))
		return
	data = fd.read(SECTOR_SIZE * 2048)
	fd.close()
	for i in xrange(0, ((len(data)/SECTOR_SIZE) - 1)):
		#print i*SECTOR_SIZE, i*SECTOR_SIZE + SECTOR_SIZE
		block = data[i*SECTOR_SIZE:(i*SECTOR_SIZE) + SECTOR_SIZE]
		#if i < 20:
		#	print "block count: %d  index: %d" % (i, (i*SECTOR_SIZE))
		#	pprint(block, 32)
		#	print ""
		#else:
		#	return
		if i < 20:
			#structure items and names PGPdiskOnDiskUserInfoHeader
			# H - WORD size
			# B - BYTE type
			# B - BYET version
			# L - DWORD magic
			# B - BYTE totalRecords
			# B - BYTE currentRecord
			# H - WORD reserved
			# 
			#
			header = struct.unpack("H B B L B B H ", block[0:12])
			#				magic						type		 		currentRecord
			if header[3] == 0x57446900 and header[2] == 0x01 and header[5] == 0x00:
				#TODO:parse it
				print "here! type 1 block", i*SECTOR_SIZE
			#				magic						type		 		currentRecord
			if header[3] == 0x57446900 and header[2] == 0x02 and header[5] == 0x00:
				#TODO: parse it
				print "here! type 2 block", i*SECTOR_SIZE
			#				magic						type		 		currentRecord
			if header[3] == 0x57446900 and header[2] == 0x08 and header[5] == 0x00:
				# structure items and names PGPdiskOnDiskUserInfoHeader
				# H - WORD size
				# B - BYTE type
				# B - BYTE version
				# L - DWORD magic
				# B - BYTE totalRecords
				# B - BYTE currentRecord
				# 2s - CHAR[2] reserved		
				# END
				#
				# PGPdiskOnDiskUserInfoMain
				# H - WORD userFlags
				# L - DWORD  serialNumber
				# H - WORD localID
				# 6s - CHAR[6] reserved
				# END
				#
				# PGPdiskOnDIskUserSymm
				# H - WORD size
				# B - BYTE symmAlg
				# H - WORD totalESKsize
				# 3s - CHAR[3] reserved1
				# 128s - CHAR[128] userName
				# B - BYTE s2ktype
				# I - DWORD hashIterations
				# 3s - CHAR[3] reserved2
				# 16s - CHAR[16] salt
				# 144s - CHAR[144] esk
				#END
				#
				print "here! type 8 block", i*SECTOR_SIZE
				#PGPdiskOnDiskUserInfoHeader 
				PGPdiskOnDiskUserInfoHeader = "H B B L B B 2s"
				#PGPdiskOnDiskUserInfoMain
				PGPdiskOnDiskUserInfoMain = "H 4c H 6s"
				#PGPdiskOndiskUserSymm
				PGPdiskOnDiskUserInfoSymm = "H B H 3s 128s B I 3s 16s 144s"

				structFormat = PGPdiskOnDiskUserInfoHeader + " " + PGPdiskOnDiskUserInfoMain + " " + PGPdiskOnDiskUserInfoSymm
				structSize = struct.calcsize(PGPdiskOnDiskUserInfoHeader) 
				structSize += struct.calcsize(PGPdiskOnDiskUserInfoMain) 
				structSize += struct.calcsize(PGPdiskOnDiskUserInfoSymm) - 2
				print structSize
				unpacked = struct.unpack(structFormat, block[0:structSize])
				infoHeader_size = unpacked[0]
				infoHeader_type = unpacked[1]
				infoHeader_version = unpacked[2]
				infoHeader_magic = unpacked[3]
				infoHeader_totalRecords = unpacked[4]
				infoHeader_currentRecord = unpacked[5]
				infoHeader_reserved = unpacked[6]

				infoMain_userFlags = unpacked[7]
				infoMain_serialNumber = unpacked[8]
				infoMain_localID = unpacked[9]
				infoMain_reserved = unpacked[10]

				userSymm_size = unpacked[11]
				userSymm_symmAlg = unpacked[12]
				userSymm_totalESKsize = unpacked[13]
				userSymm_reserved1 = unpacked[14]
				userSymm_userName = unpacked[15]
				userSymm_s2ktype = unpacked[16]
				userSymm_hashIterations = unpacked[17]
				userSymm_reserved2 = unpacked[18]
				userSymm_salt = unpacked[19]
				userSymm_esk = unpacked[20]

				structList = structFormat.split(" ")

				#PGPdiskOnDiskUserInfoHeader
				indexFormatBegin = " ".join(structList[:0])
				indexFormatEnd = " ".join(structList[:1])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)
				print "(%d - %d) PGPdiskOnDiskUserInfoHeader WORD size: " % (blockAddressBegin, blockAddressEnd) , infoHeader_size


				indexFormatBegin = " ".join(structList[:1])
				indexFormatEnd = " ".join(structList[:2])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)				
				print "(%d - %d) PGPdiskOnDiskUserInfoHeader BYTE type: " % (blockAddressBegin, blockAddressEnd), infoHeader_type


				indexFormatBegin = " ".join(structList[:2])
				indexFormatEnd = " ".join(structList[:3])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)				
				print "(%d - %d) PGPdiskOnDiskUserInfoHeader BYTE version: " % (blockAddressBegin, blockAddressEnd), infoHeader_version


				indexFormatBegin = " ".join(structList[:3])
				indexFormatEnd = " ".join(structList[:4])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)				
				print "(%d - %d) PGPdiskOnDiskUserInfoHeader DWORD magic: " % (blockAddressBegin, blockAddressEnd), infoHeader_magic


				indexFormatBegin = " ".join(structList[:4])
				indexFormatEnd = " ".join(structList[:5])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)				
				print "(%d - %d) PGPdiskOnDiskUserInfoHeader BYTE totalRecords: " % (blockAddressBegin, blockAddressEnd), infoHeader_totalRecords


				indexFormatBegin = " ".join(structList[:5])
				indexFormatEnd = " ".join(structList[:6])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)				
				print "(%d - %d) PGPdiskOnDiskUserInfoHeader BYTE currentRecord: " % (blockAddressBegin, blockAddressEnd), infoHeader_currentRecord


				indexFormatBegin = " ".join(structList[:6])
				indexFormatEnd = " ".join(structList[:7])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)				
				print "(%d - %d) PGPdiskOnDiskUserInfoHeader CHAR[2] reserved: " % (blockAddressBegin, blockAddressEnd), infoHeader_reserved


				#PGPdiskOnDiskUserInfoMain
				indexFormatBegin = " ".join(structList[:7])
				indexFormatEnd = " ".join(structList[:8])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)
				print "(%d - %d) PGPdiskOnDiskUserInfoMain WORD userFlags: " % (blockAddressBegin, blockAddressEnd), infoMain_userFlags


				indexFormatBegin = " ".join(structList[:8])
				indexFormatEnd = " ".join(structList[:9])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)				
				print "(%d - %d) PGPdiskOnDiskUserInfoMain DWORD serialNumber: " % (blockAddressBegin, blockAddressEnd), infoMain_serialNumber


				indexFormatBegin = " ".join(structList[:9])
				indexFormatEnd = " ".join(structList[:10])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)				
				print "(%d - %d) PGPdiskOnDiskUserInfoMain WORD localID: " % (blockAddressBegin, blockAddressEnd), infoMain_localID


				indexFormatBegin = " ".join(structList[:10])
				indexFormatEnd = " ".join(structList[:11])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)				
				print "(%d - %d) PGPdiskOnDiskUserInfoMain CHAR[6] reserved: " % (blockAddressBegin, blockAddressEnd), infoMain_reserved

				#PGPdiskOnDiskUserInfoSYmm
				indexFormatBegin = " ".join(structList[:11])
				indexFormatEnd = " ".join(structList[:12])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)	
				print "(%d - %d) PGPdiskOndiskUserSymm size: " % (blockAddressBegin, blockAddressEnd), userSymm_size

				indexFormatBegin = " ".join(structList[:12])
				indexFormatEnd = " ".join(structList[:13])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)					
				print "(%d - %d) PGPdiskOndiskUserSymm symmAlg: " % (blockAddressBegin, blockAddressEnd), userSymm_symmAlg

				indexFormatBegin = " ".join(structList[:13])
				indexFormatEnd = " ".join(structList[:14])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)					
				print "(%d - %d) PGPdiskOndiskUserSymm totalESKsize: " % (blockAddressBegin, blockAddressEnd), userSymm_totalESKsize

				indexFormatBegin = " ".join(structList[:14])
				indexFormatEnd = " ".join(structList[:15])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)					
				print "(%d - %d) PGPdiskOndiskUserSymm reserved1: " % (blockAddressBegin, blockAddressEnd), userSymm_reserved1

				indexFormatBegin = " ".join(structList[:15])
				indexFormatEnd = " ".join(structList[:16])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)					
				print "(%d - %d) PGPdiskOndiskUserSymm userName: " % (blockAddressBegin, blockAddressEnd), userSymm_userName

				indexFormatBegin = " ".join(structList[:16])
				indexFormatEnd = " ".join(structList[:17])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)					
				print "(%d - %d) PGPdiskOndiskUserSymm s2ktype: " % (blockAddressBegin, blockAddressEnd), userSymm_s2ktype

				indexFormatBegin = " ".join(structList[:17])
				indexFormatEnd = " ".join(structList[:18])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)	
				print "(%d - %d) PGPdiskOndiskUserSymm hashIterations: " % (blockAddressBegin, blockAddressEnd), userSymm_hashIterations

				indexFormatBegin = " ".join(structList[:18])
				indexFormatEnd = " ".join(structList[:19])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)					
				print "(%d - %d) PGPdiskOndiskUserSymm reserved2: " % (blockAddressBegin, blockAddressEnd), userSymm_reserved2

				indexFormatBegin = " ".join(structList[:19])
				indexFormatEnd = " ".join(structList[:20])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)					
				print "(%d - %d) PGPdiskOndiskUserSymm salt: " % (blockAddressBegin, blockAddressEnd), userSymm_salt

				indexFormatBegin = " ".join(structList[:20])
				indexFormatEnd = " ".join(structList[:21])
				blockAddressBegin = i*SECTOR_SIZE+struct.calcsize(indexFormatBegin)
				blockAddressEnd = i*SECTOR_SIZE+struct.calcsize(indexFormatEnd)					
				print "(%d - %d) PGPdiskOndiskUserSymm esk: " % (blockAddressBegin, blockAddressEnd), userSymm_esk


			#				magic						type		 		currentRecord
			if header[3] == 0x57446900 and header[2] == 0x0c and header[5] == 0x00:
				#TODO: parse it
				print "here! type 12 block", i*SECTOR_SIZE

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s [PGP WDE Disk Image]\n" % sys.argv[0])
        sys.stderr.write("\nExample: %s rawFile\n" % sys.argv[0])
        
    for i in xrange(1, len(sys.argv)):
        processFile(sys.argv[i])