#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(19558);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2013/10/22 20:47:02 $");

 script_cve_id("CVE-2005-0357", "CVE-2005-0358", "CVE-2005-0359");
 script_bugtraq_id(14582);
 script_osvdb_id(18800, 18801, 18802);

 script_name(english:"EMC Legato Networker Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running one of the following products :

 - Legato Networker
 - Sun StorEdge Enterprise Backup Software
 - Sun Solstice Backup Software
 - Informix Storage Manager

The installed version of this software is vulnerable to denial of
service, unauthorized access and remote command execution attacks." );
 # http://web.archive.org/web/20060318052452/http://www.legato.com/support/websupport/product_alerts/081605_NW-7x.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f5513702");
 # http://web.archive.org/web/20080509045538/http://sunsolve.sun.com/search/document.do?assetkey=1-26-101886-1
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c234b0c");
 script_set_attribute(attribute:"solution", value:
"If using Legato Networker, upgrade as necessary to NetWorker 7.1.3
and 7.2 and apply the vendor's patch. 

Otherwise, apply the appropriate fix as described in Sun's advisory 
above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/16");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:legato_networker");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:solstice_backup");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:storedge_enterprise_backup_software");
 script_end_attributes();

 script_summary(english:"Determines if Legato Networker is vulnerable");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencies ("legato_detect.nasl");
 script_require_keys ("LegatoNetworker/installed");
 script_require_ports(7938);
 exit(0);
}

if (! get_kb_item("LegatoNetworker/installed") )
  exit (0);

if (islocalhost())
  exit (0);


port = 7938;
soc = open_sock_tcp (port);
if (!soc) exit(0);

rpc_port1 = rand() % 256;
rpc_port2 = rand() % 256;

xid1 = rand() % 256;
xid2 = rand() % 256;
xid3 = rand() % 256;
xid4 = rand() % 256;

pack = 
raw_string(	0x80, 0, 0, 0x38,	# Last fragment; fragment length = 40
		xid1, xid2, xid3, xid4,	# XID
		0, 0, 0, 0,		# Call
		0, 0, 0, 2,		# RPC version = 2
		0, 1, 0x86, 0xA0,	# Programm = portmapper (10000)
		0, 0, 0, 2,		# Program version = 2
		0, 0, 0, 1,		# Procedure = 1 (SET)
		0, 0, 0, 0, 0, 0, 0, 0,	# Null credential
		0, 0, 0, 0, 0, 0, 0, 0,	# Null verifier
		0, 0x54, 0x4E, 0x53,	# Program
		0, 0, 0, 1,		# Version = 1
		0, 0, 0, 6,		# Protocol = TCP
		0, 0, rpc_port1, rpc_port2	# Port
	);

send(socket: soc, data: pack);
r = recv(socket: soc, length: 32);

if ((strlen(r) != 32) || (ord(r[0]) != 0x80))
  exit (0);

reply = substr(r, 28, 31);

if ("0000001" >!< hexstr(reply))
  exit (0);

xid1 = rand() % 256;
xid2 = rand() % 256;
xid3 = rand() % 256;
xid4 = rand() % 256;

pack = 
raw_string(	0x80, 0, 0, 0x38,	# Last fragment; fragment length = 40
		xid1, xid2, xid3, xid4,	# XID
		0, 0, 0, 0,		# Call
		0, 0, 0, 2,		# RPC version = 2
		0, 1, 0x86, 0xA0,	# Programm = portmapper (10000)
		0, 0, 0, 2,		# Program version = 2
		0, 0, 0, 2,		# Procedure = 2 (UNSET)
		0, 0, 0, 0, 0, 0, 0, 0,	# Null credential
		0, 0, 0, 0, 0, 0, 0, 0,	# Null verifier
		0, 0x54, 0x4E, 0x53,	# Program
		0, 0, 0, 1,		# Version = 1
		0, 0, 0, 6,		# Protocol = TCP
		0, 0, rpc_port1, rpc_port2	# Port	
	);

send(socket: soc, data: pack);
r = recv(socket: soc, length: 32);

if ((strlen(r) != 32) || (ord(r[0]) != 0x80))
  exit (0);

reply = substr(r, 28, 31);
if ("00000001" >< hexstr(reply))
  security_hole(port);
