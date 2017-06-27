#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10063);
 script_version ("$Revision: 1.34 $");
 script_cve_id("CVE-1999-1509");
 script_bugtraq_id(773);
 script_osvdb_id(54);

 script_name(english:"Eserv GET Request Traversal Arbitrary File Access");
 script_summary(english:"\..\..\file.txt");
 
 script_set_attribute( attribute:"synopsis", value:
"The web server running on the remote host has a directory traversal
vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The version of Eserv running on the remote host is vulnerable to a
directory traversal attack.  It is possible to read arbitrary files
on the server by prepending ../../ or ..\..\ in front of the file
name.  A remote attacker could exploit this to read arbitrary files on
the server, which could be used to mount further attacks." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://marc.info/?l=bugtraq&m=94183041514522&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to Eserv 2.99 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/11/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/11/05");
 script_cvs_date("$Date: 2011/03/11 21:52:32 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 1999-2011 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports(3128);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3128);

url1 = "..\\..\\..\\..\\..\\..\\windows\\win.ini";
url2 = "..\\..\\..\\..\\..\\..\\winnt\\win.ini";

soc = http_open_socket(port);
if(soc)
{
 r = http_send_recv3(method:"GET", item:url1, port:port);
 if (isnull(r)) exit(1, "The server didn't respond to the GET request.");

 if("[windows]" >< r[2]){
 	security_warning(port);
	exit(0);
	}

 r = http_send_recv3(method:"GET", item:url2, port:port);
 if (isnull(r)) exit(1, "The server didn't respond to the GET request.");
 if("[fonts]" >< r[2]){
 	security_warning(port);
	exit(0);
	}
}

