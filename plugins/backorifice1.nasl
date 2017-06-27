a =0x4c;
s = raw_string(0xCE, 0x63, 0xD1, 0xD2, 0x16, 0xE7,
	       0x13, 0xCF, 0x39, 0xA5, 0xA5, 0x86,
	       0x4D, 0x8A, 0xB4, 0x66, 0xAA, 0x32);
/*#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10024);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2013/02/15 02:47:02 $");

 script_name(english:"BackOrifice Software Detection");
 script_summary(english:"Determines the presence of BackOrifice");

 script_set_attribute(attribute:"synopsis", value:"The remote host has a backdoor program installed.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running BackOrifice 1.x with no password. 
BackOrifice is a trojan which allows an intruder to take control of the
remote computer.");
 script_set_attribute(attribute:"solution", value:"Remove BackOrifice from your computer.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/29");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2013 Tenable Network Security, Inc.");
 script_family(english:"Backdoors");

 script_dependencie("os_fingerprint.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include('global_settings.inc');

if (!thorough_tests) audit(AUDIT_THOROUGH);

os = get_kb_item("Host/OS");
if (os)
{
 if ("Windows" >!< os) audit(AUDIT_OS_NOT, "Windows");
}

port = 31337;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

#
# Reverse-engineered data. Not very meaningful.
# This is a 'ping' request for BackOrifice
#

s = raw_string(0xCE, 0x63, 0xD1, 0xD2, 0x16, 0xE7,
	       0x13, 0xCF, 0x39, 0xA5, 0xA5, 0x86,
	       0x4D, 0x8A, 0xB4, 0x66, 0xAA, 0x32);

send(socket:soc, data:s, length:18);
r = recv(socket:soc, length:10);
if(r)security_hole(port:port, proto:"udp");
close(soc);*/
