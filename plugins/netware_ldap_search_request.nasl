#
# This script was written by David Kyger <david_kyger@symantec.com>
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/3/09)
# - Replaced broken URL, added URL comment and CPE, updated copyright (10/18/2012)


include("compat.inc");

if (description)
{
 script_id(12104);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");

 script_name(english:"Novell NetWare LDAP Server Anonymous Bind"); 

 script_set_attribute(attribute:"synopsis", value:
"Information can be read on the remote LDAP server." );
 script_set_attribute(attribute:"description", value:
"The server's directory base is set to NULL. This allows information to be 
enumerated without any prior knowledge of the directory structure." );
  # http://web.archive.org/web/20050104194650/http://support.novell.com/cgi-bin/search/searchtid.cgi?/10077872.htm
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?569899d0" );
 script_set_attribute(attribute:"solution", value:
"Disable or restrict anonymous binds in LDAP if not required." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/03/15");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/o:novell:netware");
script_end_attributes();

 script_summary(english:"Use LDAP search request to retrieve information from a Novell NetWare Server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 David Kyger");
 script_family(english:"Netware");
 script_dependencies("ldap_detect.nasl");
 script_require_ports("Services/ldap", 389);
 exit(0);
}
#
# The script code starts here
#
include("misc_func.inc");
port = get_kb_item("Services/ldap");
if (!port) port = 389;
if ( ! get_port_state(port) ) exit(0);
flag = 0;

warning = "The following information was pulled from the server via a LDAP request:\n";

senddata = raw_string(
0x30, 0x25, 0x02, 0x01, 0x02, 0x63, 0x20, 0x04, 0x00, 0x0a, 
0x01, 0x02, 0x0a, 0x01, 0x00, 0x02, 0x01, 0x00, 0x02, 0x01, 
0x00, 0x01, 0x01, 0x00, 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 
0x63, 0x74, 0x63, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x00
			);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);
send(socket:soc, data:senddata);
buf = recv(socket:soc, length:4096);
close(soc);
version = string(buf);

if (buf == NULL) exit(0);

hbuf = hexstr(buf);


if ("Novell" >< buf) {
	hostname = strstr(hbuf, "4c44415020536572766572");
	hostname = hostname - strstr(hostname, "304f302b04075665");
	hostname = hex2raw(s:hostname);

        if (!isnull(hostname)) {
		warning += string(hostname,"\n");
		flag = 1;
		}
	}

if ("LDAP Server" >< buf) {
	version = strstr(hbuf, "4e6f76656c6c");
	version = version - strstr(version, "300d");
	version = hex2raw(s:version);

	if (!isnull(version)) {
		warning += string(version);
		flag = 1;
		}
	}

if (flag == 1) {
security_warning(port:port, extra:warning);
}

