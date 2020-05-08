#!/bin/python
import ldap
import os
import time
from getpass import getpass

# Disable cert check
#ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

password = getpass()

outdir="policy_dump_" + time.strftime("%Y%m%d_%H%M%S")

connect = ldap.initialize('ldaps://xxx.xxx.xxx.xxx:yyyy')

connect.set_option(ldap.OPT_REFERRALS, 0)
connect.simple_bind_s('cn=admin,ou=system,o=idm', password)

BASE="cn=Driver Set,ou=System,o=IDM"

result = connect.search_s(BASE,
                          ldap.SCOPE_SUBTREE,
                          'objectClass=DirXML-Rule',
                          ['XmlData'])
os.mkdir(outdir)

for x in result:
    outfile=os.path.join(outdir,str(x[0]))
    f = open(outfile, "a")
    f.write(str (x[1]['XmlData'][0]))
    f.close()

connect.unbind()