#
# (C) Tenable Network Security, Inc.
#

# Ref:
#  Date: Thu, 05 Jun 2003 11:08:44 -0500
#  From: KF <dotslash@snosoft.com>
#  To: bugtraq@securityfocus.com
#  Subject: SRT2003-06-05-0935 - HPUX ftpd remote issue via REST
#

include("compat.inc");

if (description)
{
 script_id(11701);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2014/08/29 21:03:42 $");

 script_bugtraq_id(7825);
 script_osvdb_id(51721);

 script_name(english:"HP-UX FTPD REST Command Remote Arbitrary Memory Disclosure");
 script_summary(english:"Checks if the remote ftp sanitizes the RETR command");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to disclose the contents of the memory of the remote
host");
 script_set_attribute(attribute:"description", value:
"The remote FTP server seems to be vulnerable to an integer conversion
bug when it receives a malformed argument to the 'REST' command.

An attacker may exploit this flaw to force the remote FTP daemon to
disclose portions of the memory of the remote host.");
 script_set_attribute(attribute:"solution", value:"If the remote FTP server is HP-UX ftpd, then apply patch PHNE_21936.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/06");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

login = get_kb_item_or_exit("ftp/login");
pass  = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);;

banner = get_ftp_banner(port:port);
if (! banner) exit(1);

# ProFTPD may seem vulnerable, but actually checks the REST argument
# at download time.
if("ProFTPD" >< banner || "Version wu-" >< banner || "Version wuftpd-" >< banner)exit(0);

if ( " FTP server" >!< banner ) exit(0);

if ( "PHNE_31931" >< banner || "PHNE_30990" >< banner ) exit(0);

soc = open_sock_tcp(port);
if (!soc) exit(1);

if (! ftp_authenticate(socket:soc, user:login, pass:pass ) )
  exit(1);

 send(socket:soc, data:'REST 1111111111111111\r\n');
 r = recv_line(socket:soc, length:4096);
 ftp_close(socket:soc);
 if("2147483647" >< r ) security_hole(port);
