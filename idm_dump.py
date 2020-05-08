#!/bin/python

import ldap
import os
import time
from getpass import getpass

# Disable cert check
#ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)

BASE="cn=Driver Set,ou=System,o=IDM"
ADMIN_USER='cn=admin,ou=system,o=idm'
outdir="idm_dump_" + time.strftime("%Y%m%d_%H%M%S")

systems = [("sys", 'ldaps://<adr>:<port>'),
           ("acc", 'ldaps://<adr>:<port>')]


def write_file(outdir, obj_name, value, type_suffix = None):
    delim = "_"
    if type_suffix is None:
        delim = ""
        type_suffix = ""
    outfile=os.path.join(outdir, obj_name + delim + type_suffix + ".xml")
    f = open(outfile, "a")
    try:
        f.write(value)
    except Exception as e:
        print "Exception for " + obj_name  + ": " + str(e)
    finally:
        f.close()

def dump_rules(conn, outdir):
    result = conn.search_s(BASE,
                              ldap.SCOPE_SUBTREE,
                              'objectClass=DirXML-Rule',
                              ['XmlData'])
    target_dir = os.path.join(outdir,"policies")
    os.mkdir(target_dir)
    for x in result:
        try:
            write_file(target_dir, str(x[0]), str (x[1]['XmlData'][0]))
        except KeyError as e:
            print "Exception for " + str(x[0])  + ": " + str(e)

def dump_gcvs(conn, outdir):
    result = conn.search_s(BASE,
                              ldap.SCOPE_SUBTREE,
                              'objectClass=DirXML-GlobalConfigDef',
                              ['DirXML-ConfigValues'])
    target_dir = os.path.join(outdir,"gcv")
    os.mkdir(target_dir)
    for x in result:
        try:
            write_file(target_dir, str(x[0]), str (x[1]['DirXML-ConfigValues'][0]))    
        except KeyError as e:
            print "Exception for " + str(x[0])  + ": " + str(e)

def dump_prds(conn, outdir):
    result = conn.search_s(BASE,
                              ldap.SCOPE_SUBTREE,
                              'objectClass=srvprvRequest',
                              ['srvprvProcessXML',
                               'srvprvRequestXML',
                               'XmlData'])
    target_dir = os.path.join(outdir,"prd")
    os.mkdir(target_dir)
    for x in result:
        try:
            write_file(target_dir, str(x[0]), str (x[1]['srvprvProcessXML'][0]), "process")
        except KeyError as e:
            print "Exception for " + str(x[0])  + ": " + str(e)
        try:
            write_file(target_dir, str(x[0]), str (x[1]['srvprvRequestXML'][0]), "request")
        except KeyError as e:
            print "Exception for " + str(x[0])  + ": " + str(e)
        try:
            write_file(target_dir, str(x[0]), str (x[1]['XmlData'][0]), "data")
        except KeyError as e:
            print "Exception for " + str(x[0])  + ": " + str(e)


def do_dump(conn, env):
    my_outdir = os.path.join(outdir,env)
    os.mkdir(my_outdir)
    dump_rules(conn,my_outdir)
    dump_gcvs(conn,my_outdir)
    dump_prds(conn,my_outdir)


##### MAIN #####
password = getpass()

os.mkdir(outdir)

for system in systems:
    print "Dumping " + system[0]
    connect = ldap.initialize(system[1])
    connect.set_option(ldap.OPT_REFERRALS, 0)
    connect.simple_bind_s(ADMIN_USER, password)
    do_dump(connect, system[0])
    connect.unbind()


