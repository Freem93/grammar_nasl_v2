#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(22870);
 script_version ("$Revision: 1.16 $");
 script_cvs_date("$Date: 2017/03/03 22:16:03 $");

 script_name(english:"Ariel FTP Server Default 'document' Account");
 script_summary(english:"Checks if it is possible to log into the remote FTP server as the 'document' user.");
	     
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server can be accessed with a known login and password
pair.");
 script_set_attribute(attribute:"description", value:
"The remote host is an Ariel FTP server. Ariel is a document
transmission system mostly used in the academic world.

Nessus was able to log into the remote FTP server by connecting as the
user 'document' (or 'ariel4') and with a hex-encoded password based on
the IP address of the host the user is connecting from. 

An attacker could log into the server and obtain the files from the
print queue or use the remote storage space for anything else.");
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to this port.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"default_account", value:"true");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

 script_dependencies("DDI_FTP_Any_User_Login.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_exclude_keys("global_settings/supplied_logins_only");

 exit(0);
}

#
# The script code starts here : 
#

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");
include("byte_func.inc");
include("misc_func.inc");

port = get_ftp_port(default: 419);

if (get_kb_item("ftp/"+port+"/AnyUser"))
  audit(AUDIT_FTP_RANDOM_USER, port);

banner = get_ftp_banner(port:port);
if ( banner !~ "^220 FTP ready\." )
 exit(0, "The FTP on port "+port+" is not Ariel.");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

ip = split(this_host(), sep:'.', keep:FALSE);
for ( i = 0 ; i < 4 ; i ++ )
 pass += hexstr(mkbyte(int(ip[i])));

user = 'document';
pass = str_replace(string:toupper(pass), find:"0", replace:"#");

if ( ! ftp_authenticate(socket:soc, user:'document', pass:pass) ) 
{
 user = 'ariel4';
 close(soc);
 soc = open_sock_tcp(port);
 if (! soc) audit(AUDIT_SOCK_FAIL, port);
 if ( ! ftp_authenticate(socket:soc, user:'ariel4', pass:pass) )
  audit(AUDIT_LISTEN_NOT_VULN, "FTP", port);
}

port2 = ftp_pasv(socket:soc);
if ( ! port2 ) exit(1, "PASV command (control port=", port, ").");

soc2 = open_sock_tcp(port2);
if (! soc2) audit(AUDIT_SOCK_FAIL, port2);


send(socket:soc, data:'LIST\r\n');
buf = recv(socket:soc, length:4096);
listing = ftp_recv_listing(socket:soc2);
close(soc2);
close(soc);

report = 'It was possible to log in as \'' + user + '\'/\''+pass+'\'\n' + 'The output of the root directory is :\n\n' + listing;

if (report_verbosity > 0) 
  security_hole(port:port, extra:report);
else
  security_hole(port);
