#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11757);
 script_bugtraq_id(7900);
 script_osvdb_id(50481);
 script_xref(name:"Secunia", value:"9036");

 script_version ("$Revision: 1.16 $");
 
 script_name(english:"NGC Active FTPServer 2002 Multiple Command Remote DoS");
 script_summary(english:"NGC ActiveFTP check.");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a remote denial of service
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Active FTP server, a shareware
FTP server for Windows-based systems.

There is a flaw in the version of ActiveFTP which may allow an
attacker to crash this service remotely by sending an overly long
argument to various FTP commands (USER, CWD, and more). The attack can
only be performed without authentication through the USER command.

A successful exploit will result in a denial of service and may
potentially allow the attacker to execute arbitrary code in the context
of the affected application.");
 
 script_set_attribute(attribute:"see_also", value:"http://secunia.com//advisories/9036/");
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");


 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/18");
 script_cvs_date("$Date: 2016/09/23 20:00:43 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);


#
# This service can not be crashed reliably, we only rely on the banner 
# (ie: no safe_checks/no safe checks).
#

banner = get_ftp_banner(port:port);
if(!banner) exit(1, "Cannot read FTP banner on port "+port+".");
if("Welcome to NGC Active FTPServer" >< banner) { security_hole(port); exit(0); }
