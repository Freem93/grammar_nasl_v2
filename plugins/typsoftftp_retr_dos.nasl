#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14699);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2011/03/11 20:33:10 $");

 script_bugtraq_id(11131);
 script_osvdb_id(9433);

 script_name(english:"TYPSoft FTP Server Crafted RETR Command Sequence Remote DoS");
 script_summary(english:"Checks for version of TYPSoft FTP server");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
denial of service vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running TYPSoft FTP 1.11 or 
earlier. TYPSoft FTP Server is prone to a remote denial of 
service vulnerability that may allow an attacker to cause 
the server to crash by sending a malformed 'RETR' command 
to the remote server" );
 script_set_attribute(attribute:"solution", value:
"Use a different FTP server or upgrade to the newest 
version." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/31");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"FTP");

 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/typsoftftp");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (! banner) exit(1, "No FTP banner on port "+port+".");
if (
  egrep(pattern:".*TYPSoft FTP Server (0\.|1\.[0-9][^0-9]|1\.1[01][^0-9])", string:banner)
) security_warning(port);
