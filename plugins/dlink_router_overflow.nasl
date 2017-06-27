#
# (C) Tenable Network Security, Inc.
# 

#
# Ref: 
#  Date: 26 May 2003 05:53:41 -0000
#  From: Chris R <admin@securityindex.net>
#  To: bugtraq@securityfocus.com
#  Subject: Buffer Overflow? Local Malformed URL attack on D-Link 704p router


include("compat.inc");

if(description)
{
 script_id(11655);
 script_version ("$Revision: 1.13 $");
 script_osvdb_id(55108);
 script_cvs_date("$Date: 2013/01/25 01:19:07 $");
 
 script_name(english:"D-Link 704p Web Interface syslog.htm Malformed Query Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The remote host is a D-Link router running a firmware version
older than, or as old as 2.70.

There is a flaw in this version which may allow an attacker
to crash the remote device by sending an overly long
argument to the 'syslog.htm' page." );
 script_set_attribute(attribute:"solution", value:
"None at this time. Filter incoming traffic to this port." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
		 
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/27");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks the firmware version of the remote D-Link router");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_require_ports("Services/www", 80);
 script_dependencies("http_version.nasl");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 1);

r = http_send_recv3(method: "GET", item:"/syslog.htm", port:port);
res = strcat(r[0], r[1], '\r\n', r[2]);
 if( "DI-704P" >< res )
 {
   vers = egrep(pattern:"^<TR><TD><HR>WAN Type:.*</BR>", string:res);
   if( vers == NULL ) exit(0);
   
   if(ereg(pattern:".*V(1\.|2\.([0-6][0-9]|70))", string:vers))security_hole(port);
 }

