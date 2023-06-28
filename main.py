############## sOSCARed ###############
# A free and open source OSCAR server #
#######################################

import socketserver
import random
import threading
import hashlib
import uuid
import sys
import time
import base64
from oscar import *

# placeholder "database"
db = {
	"uuid": uuid.uuid4(),
	"users": {
		"janLuna": {
			"authkey": "phoenix",
			"pwhash": "aa56d3853c51675b74ac797061363c59",
			"email": "janLuna@example.com",
			"evilLevel": 0,
		}
	}
}

clients = {}

class LoginHandler(socketserver.BaseRequestHandler):
	def setup(self):
		self.sequence = random.randint(0,255)

	def send(self,frame,data=b""):
		self.request.sendall(FLAP(FLAP_MARKER,frame,self.sequence,len(data),data=data).get_FLAP())
		self.sequence += 1

	def handle(self):
		self.send(FLAP_FRAME.SIGNON)
		while True:
			header = self.request.recv(6)
			if header == b"":
				break
			flap = parse_FLAP_header(header)
			flap.data = self.request.recv(flap.length)
			match flap.frame:
				case FLAP_FRAME.SIGNON:
					print("signon")
					print(flap.data)
				case FLAP_FRAME.DATA:
					self.SNAC_handler(flap.data)
				case FLAP_FRAME.SIGNOFF:
					print("signoff")
					self.request.close()
					break
				case _:
					print("unhandled FLAP_FRAME:",flap.frame)

	def get_authkey(self,user: str):
		authkey = db["users"][user]["authkey"]
		return bytes(authkey,"utf-16")

	def check_password(self,user: str,pwHash: str):
		authkey = self.get_authkey(user)
		# pw = db["users"][user]["password"]
		# cPwHash = hashlib.md5(bytes(pw,"ascii")+AUTH_HASH_MD5).hexdigest()
		# print(cPwHash,pwHash)
		cPwHash = db["users"][user]["pwhash"]
		return cPwHash == pwHash
		# return True

	def get_authcookie(self, user):
		cookie = uuid.uuid5(db["uuid"],str(time.time()//30)+user+db["users"][user]["pwhash"])
		return base64.encodebytes(bytes(user,"utf-8")+b"COOKIESTARTSHERE"+cookie.bytes)

	def get_email(self,user):
		email = db["users"][user]["email"]
		return bytes(email,"utf-8")

	def SNAC_handler(self,data):
		snac = parse_SNAC(data)
		print(snac.foodgroup,snac.subgroup)
		print(snac.data)
		match snac.foodgroup:
			case FOODGROUPS.BUCP:
				match snac.subgroup:
					case BUCP.CHALLENGE_REQUEST:
						tlvs = parse_TLVs(snac.data)
						username = None
						for i in tlvs:
							match i.type:
								case b"\x00\x01":
									username = str(i.value,"utf-8")
								case _:
									print("unhandled TLV:",i.type)
						if username != None:
							self.username = username
						else:
							self.socket.close()
						authkey = self.get_authkey(username)
						resData = len(authkey).to_bytes(2,"big")+authkey
						response = SNAC(FOODGROUPS.BUCP,BUCP.CHALLENGE_RESPONSE,bytes(2),snac.id,resData)
						print("sussy balls", response.as_bytes().hex())
						self.send(FLAP_FRAME.DATA,response.as_bytes())
					case BUCP.LOGIN_REQUEST:
						tlvs = parse_TLVs(snac.data)
						passwordHash = None
						username = None
						for i in tlvs:
							match i.type:
								case b"\x00\x01":
									username = str(i.value,"utf-8")
								case b"\x00\x25":
									passwordHash = i.value.hex()
									print(passwordHash)
									print(i.value)
								case _:
									print("unhandled TLV:",i.type)
						if None in (passwordHash, username): 
							response = SNAC(FOODGROUPS.BUCP,BUCP.LOGIN_RESPONSE,bytes(2),snac.id,TLV(b"\0\x08",2,b"\0\x01").as_bytes())
							self.send(FLAP_FRAME.DATA, response.as_bytes())
							self.request.close()
							sys.exit()
						if self.check_password(username,passwordHash) == False:
							response = SNAC(FOODGROUPS.BUCP,BUCP.LOGIN_RESPONSE,bytes(2),snac.id,TLV(b"\0\x08",2,b"\0\x04").as_bytes())
							self.send(FLAP_FRAME.DATA, response.as_bytes())
							self.request.close()
							sys.exit()
						authcookie = self.get_authcookie(username)
						email = self.get_email(username)
						resTLVs = []
						resTLVs.append(TLV(b"\0\x01",len(self.username),bytes(self.username,"utf-8")))
						BOS_ADDRESS = b"localhost:5191"
						resTLVs.append(TLV(b"\0\x05",len(BOS_ADDRESS),BOS_ADDRESS)) # BOS address TLV
						resTLVs.append(TLV(b"\0\x06",len(authcookie),authcookie)) # authcookie TLV
						resTLVs.append(TLV(b"\0\x11",len(email),email)) # email tlv
						resData = b"".join([i.as_bytes() for i in resTLVs])
						print(resData)
						response = SNAC(FOODGROUPS.BUCP,BUCP.LOGIN_RESPONSE,bytes(2),snac.id,resData)
						self.send(FLAP_FRAME.DATA,response.as_bytes())
					case _:
						print("unhandled BUCP subgroup:",snac.subgroup)
			case _:
				print("unhandled foodgroup:",snac.foodgroup)

class BOSSHandler(socketserver.BaseRequestHandler):
	def setup(self):
		self.sequence = random.randint(0,255)
		print("got BOSS connection!")
		self.supFOODGROUPS = (FOODGROUPS.OSERVICE,)
		self.fg_versions = ((FOODGROUPS.OSERVICE,4),)

	def send(self,frame,data=b""):
		self.request.sendall(FLAP(FLAP_MARKER,frame,self.sequence,len(data),data=data).get_FLAP())
		self.sequence += 1

	def check_authcookie(self,cookie):
		a = base64.decodebytes(cookie)
		user,cookie= a.split(b"COOKIESTARTSHERE")
		user = str(user,"utf-8")
		if cookie in [uuid.uuid5(db["uuid"],str(time.time()//30)+user+db["users"][user]["pwhash"]).bytes,uuid.uuid5(db["uuid"],str(time.time()//30-1)+user+db["users"][user]["pwhash"]).bytes]:
			self.user = user
			return True
		else:
			return False

	def handle(self):
		self.send(FLAP_FRAME.SIGNON,b"\0\0\0\x01")
		while True:
			header = self.request.recv(6)
			if header == b"":
				break
			flap = parse_FLAP_header(header)
			flap.data = self.request.recv(flap.length)
			match flap.frame:
				case FLAP_FRAME.SIGNON:
					print("signon")
					reqTLVs = parse_TLVs(flap.data[4:])
					print(flap.data)
					authcookie = None
					for i in reqTLVs:
						if i.type == b"\0\x06":
							authcookie = i.value
					if authcookie == None or not self.check_authcookie(authcookie):
						print("krill your shelf")
						self.request.close()
						break
					honlineData = b"".join(self.supFOODGROUPS)
					honlineSNAC = SNAC(FOODGROUPS.OSERVICE,OSERVICE.HOST_ONLINE,bytes(2),69,honlineData)
					self.send(FLAP_FRAME.DATA,honlineSNAC.as_bytes())
				case FLAP_FRAME.DATA:
					self.SNAC_handler(flap.data)
				case FLAP_FRAME.KEEP_ALIVE:
					pass
				case _:
					print("unhandled FLAP_FRAME:",flap.frame)

	def SNAC_handler(self,data):
		snac = parse_SNAC(data)
		print(snac.foodgroup,snac.subgroup)
		print(snac.data)
		match snac.foodgroup:
			case FOODGROUPS.OSERVICE:
				match snac.subgroup:
					case OSERVICE.CLIENT_VERSIONS:
						self.client_foodgroups = []
						for i in range(0,len(snac.data)//4):
							y = i*4
							self.client_foodgroups.append((snac.data[y:y+2],snac.data[y+2:y+4]))
						resData = b""
						for i in self.fg_versions:
							resData += i[0]+i[1].to_bytes(2,"big")
						res = SNAC(FOODGROUPS.OSERVICE,OSERVICE.HOST_VERSIONS,bytes(2),70,resData)
						self.send(FLAP_FRAME.DATA,res.as_bytes())
					case OSERVICE.RATE_PARAMS_QUERY:
						res = SNAC(FOODGROUPS.OSERVICE,OSERVICE.RATE_PARAMS_REPLY,bytes(2),71,bytes(2))
						self.send(FLAP_FRAME.DATA,res.as_bytes())
					case OSERVICE.USER_INFO_QUERY:
						resData = len(self.user).to_bytes(1,"big")
						resData += bytes(self.user,"utf-8")
						resData += db["users"][self.user]["evilLevel"].to_bytes(2,"big")
						resData += bytes(2)
						self.send(FLAP_FRAME.DATA,SNAC(FOODGROUPS.OSERVICE,OSERVICE.USER_INFO_UPDATE,bytes(2),420,resData).as_bytes())
					case OSERVICE.CLIENT_ONLINE:
						if not self.user in clients.keys():
							clients.self.user = [self]
						else:
							clients[self.user].append(self)
					case _:
						print("unhandled OSERVICE subgroup:",snac.subgroup)
			case _:
				print("unhandled foodgroup:",snac.foodgroup)


def startLoginServer():
	with socketserver.ThreadingTCPServer(("0.0.0.0",5190),LoginHandler) as server:
		print(server.server_address)
		try:
			server.serve_forever()
		except:
			server.shutdown()
			server.server_close()

def startBossServer():
	with socketserver.ThreadingTCPServer(("0.0.0.0",5191),BOSSHandler) as server:
		print(server.server_address)
		try:
			server.serve_forever()
		except:
			server.shutdown()
			server.server_close()

loginServerThread = threading.Thread(target=startLoginServer)
bosServerThread = threading.Thread(target=startBossServer)

loginServerThread.start()
bosServerThread.start()