import bcrypt
import base64

hashedPass = b'$2b$12$SVInH5XmuS3C7eQkmqa6UOM6sDIuumJPrvuiTr.Lbz3GCcUqdf.z6'
salt = b'$2b$12$SVInH5XmuS3C7eQkmqa6UO'

file = open("/usr/share/wordlists/rockyou.txt","r")

for password in file:

	try:
		bpass = password.strip().encode('ascii','ignore')
		passed= str(base64.b64encode(bpass))
		hashAndSalt = bcrypt.hashpw(passed.encode(), salt)

		if hashAndSalt == hashedPass:
			print("Password match: ", password, hashAndSalt)
			break
	except:continue
