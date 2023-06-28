AUTOINDEX = 1
def auto(reset=False):
	global AUTOINDEX
	index = AUTOINDEX
	if reset == False:
		AUTOINDEX += 1
	else:
		AUTOINDEX = 1
	return index

class FOODGROUPS:
	OSERVICE = b"\0\x01"
	LOCATE = b"\0\x02"
	BUDDY = b"\0\x03"
	ICBM = b"\0\x04"
	ADVERT = b"\0\x05"
	INVITE = b"\0\x06"
	ADMIN = b"\0\x07"
	POPUP = b"\0\x08"
	PD = b"\0\x09"
	USER_LOOKUP = b"\0\x0A"
	STATS = b"\0\x0B"
	TRANSLATE = b"\0\x0C"
	CHAT_NAV = b"\0\x0D"
	CHAT = b"\0\x0E"
	ODIR = b"\0\x0F"
	BART = b"\0\x10"
	FEEDBAG = b"\0\x13"
	ICQ = b"\0\x15"
	BUCP = b"\0\x17"
	ALERT = b"\0\x18"
	PLUGIN = b"\0\x22"
	FG24 = b"\0\x24"
	MDIR = b"\0\x25"
	ARS = b"\x04\x4A"

FLAP_MARKER = b"*"

class FLAP_FRAME:
	SIGNON = auto().to_bytes(1,"big")
	DATA = auto().to_bytes(1,"big")
	ERROR = auto().to_bytes(1,"big")
	SIGNOFF = auto().to_bytes(1,"big")
	KEEP_ALIVE = auto(True).to_bytes(1,"big")

class BUCP:
	ERR = auto().to_bytes(2,"big")
	LOGIN_REQUEST = auto().to_bytes(2,"big")
	LOGIN_RESPONSE = auto().to_bytes(2,"big")
	REGISTER_REQUEST = auto().to_bytes(2,"big")
	REGISTER_RESPONSE = auto().to_bytes(2,"big")
	CHALLENGE_REQUEST = auto().to_bytes(2,"big")
	CHALLENGE_RESPONSE = auto().to_bytes(2,"big")
	ASASN_REQUEST = auto().to_bytes(2,"big")
	ASASN_RESPONSE = auto().to_bytes(2,"big")
	SECURID_REQUEST = auto().to_bytes(2,"big")
	SECURID_RESPONSE = auto().to_bytes(2,"big")
	REGISTRATION_IMAGE_REQUEST = auto().to_bytes(2,"big")
	REGISTRATION_IMAGE_REPLY = auto(True).to_bytes(2,"big")

class OSERVICE:
	ERR = auto().to_bytes(2,"big")
	CLIENT_ONLINE = auto().to_bytes(2,"big")
	HOST_ONLINE = auto().to_bytes(2,"big")
	SERVICE_REQUEST = auto().to_bytes(2,"big")
	SERVICE_RESPONSE = auto().to_bytes(2,"big")
	RATE_PARAMS_QUERY = auto().to_bytes(2,"big")
	RATE_PARAMS_REPLY = auto().to_bytes(2,"big")
	RATE_PARAMS_SUB_ADD = auto().to_bytes(2,"big")
	RATE_DEL_PARAM_SUB = auto().to_bytes(2,"big")
	RATE_PARAM_CHANGE = auto().to_bytes(2,"big")
	PAUSE_REQ = auto().to_bytes(2,"big")
	PAUSE_ACK = auto().to_bytes(2,"big")
	RESUME = auto().to_bytes(2,"big")
	USER_INFO_QUERY = auto().to_bytes(2,"big")
	USER_INFO_UPDATE = auto().to_bytes(2,"big")
	EVIL_NOTIFICATION = auto().to_bytes(2,"big")
	IDLE_NOTIFICATION = auto().to_bytes(2,"big")
	MIGRATE_GROUPS = auto().to_bytes(2,"big")
	MOTD = auto().to_bytes(2,"big")
	SET_PRIVACY_FLAGS = auto().to_bytes(2,"big")
	WELL_KNOWN_URLS = auto().to_bytes(2,"big")
	NOOP = auto().to_bytes(2,"big")
	CLIENT_VERSIONS = auto().to_bytes(2,"big")
	HOST_VERSIONS = auto().to_bytes(2,"big")
	MAX_CONFIG_QUERY = auto().to_bytes(2,"big")
	MAX_CONFIG_REPLY = auto().to_bytes(2,"big")
	STORE_CONFIG = auto().to_bytes(2,"big")
	CONFIG_QUERY = auto().to_bytes(2,"big")
	CONFIG_REPLY = auto().to_bytes(2,"big")
	SET_USERINFO_FIELDS = auto().to_bytes(2,"big")
	PROBE_REQ = auto().to_bytes(2,"big")
	PROBE_ACK = auto().to_bytes(2,"big")
	BART_REPLY = auto().to_bytes(2,"big")
	BART_QUERY2 = auto().to_bytes(2,"big")
	BART_REPLY2 = auto(True).to_bytes(2,"big")

class ICBM:
	ERR = auto().to_bytes(2,"big")
	ADD_PARAMETERS = auto().to_bytes(2,"big")
	DEL_PARAMETERS = auto().to_bytes(2,"big")
	PARAMETER_QUERY = auto().to_bytes(2,"big")
	PARAMETER_REPLY = auto().to_bytes(2,"big")
	CHANNEL_MSG_TOHOST = auto().to_bytes(2,"big")
	CHANNEL_MSG_TOCLIENT = auto().to_bytes(2,"big")
	EVIL_REQUEST = auto().to_bytes(2,"big")
	EVIL_REPLY = auto().to_bytes(2,"big")
	MISSED_CALLS = auto().to_bytes(2,"big")
	CLIENT_ERR = auto().to_bytes(2,"big")
	HOST_ACK = auto().to_bytes(2,"big")
	SIN_STORED = auto().to_bytes(2,"big")
	SIN_LIST_QUERY = auto().to_bytes(2,"big")
	SIN_LIST_REPLY = auto().to_bytes(2,"big")
	SIN_RETRIEVE = auto().to_bytes(2,"big")
	SIN_DELETE = auto().to_bytes(2,"big")
	NOTIFY_REQUEST = auto().to_bytes(2,"big")
	NOTIFY_REPLY = auto().to_bytes(2,"big")
	CLIENT_EVENT = auto().to_bytes(2,"big")
	SIN_REPLY = auto().to_bytes(2,"big")

AUTH_HASH_MD5 = bytes("AOL Instant Messenger (SM)","cp437")

class FLAP:
	def __init__(self,marker,frame,sequence,length=0,data=b""):
		self.marker = marker
		self.frame = frame
		self.sequence = sequence
		self.length = length
		self.data = data

	def get_header(self):
		return self.marker[:1]+self.frame[:1]+self.sequence.to_bytes(2,"big")[:2]+self.length.to_bytes(2,"big")[:2]
	
	def get_FLAP(self):
		return self.get_header()+self.data[:self.length]
	def __bytes__(self):
		return self.get_FLAP()

class SNAC:
	def __init__(self,foodgroup,subgroup,flags,id,data=b""):
		self.foodgroup = foodgroup
		self.subgroup = subgroup
		self.flags = flags
		self.id = id
		self.data = data
	def get_header(self):
		return self.foodgroup+self.subgroup+self.flags+self.id.to_bytes(4,"big")
	def as_bytes(self):
		return self.get_header() + self.data
	def __bytes__(self):
		return self.as_bytes()

class TLV:
	def __init__(self,type,length,value=b""):
		self.type = type
		self.length = length
		self.value = value
	def get_header(self):
		return self.type+self.length.to_bytes(2,"big")
	def as_bytes(self):
		return self.get_header()+self.value

def parse_FLAP_header(header):
	return FLAP(header[:1],header[1:2],int.from_bytes(header[2:4]),int.from_bytes(header[4:6]))

def parse_SNAC(snac):
	header = snac[:10]
	data = snac[10:]
	return SNAC(header[:2],header[2:4],header[4:6],int.from_bytes(header[6:]),data)

def parse_TLVs(tlvs):
	tlvs = bytearray(tlvs)
	result = []
	while len(tlvs) > 0:
		type = tlvs.pop(0).to_bytes(1,"big")+tlvs.pop(0).to_bytes(1,"big")
		length = int.from_bytes(tlvs.pop(0).to_bytes(1,"big")+tlvs.pop(0).to_bytes(1,"big"))
		value = bytearray(length)
		for i in range(0,length):
			try:
				value[i] = tlvs.pop(0)
			except:
				break
		result.append(TLV(type,length,bytes(value)))
	return result