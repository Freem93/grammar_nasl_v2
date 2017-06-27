#
# (C) Tenable Network Security, Inc.
#
# ref: http://marc.info/?l=bugtraq&m=105353283720837&w=2
#


include("compat.inc");


if(description)
{
 script_id(11648);
 script_cve_id("CVE-2003-0343");
 script_bugtraq_id(7647);
 script_osvdb_id(12079);
 script_xref(name:"Secunia", value:"8840");
 script_version ("$Revision: 1.16 $");
 
 script_name(english:"BlackMoon FTP Login Error Message User Enumeration");
 script_summary(english:"Checks for the ftp login error message");
	     
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a user enumeration vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"The version of BlackMoon FTP running on the remote host issues a
special error message when a user attempts to log in using a
nonexistent account.

An attacker may use this flaw to make a list of valid accounts,
which can be used to mount further attacks." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://marc.info/?l=bugtraq&m=105353283720837&w=2"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BlackMoon FTP."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/20");
 script_cvs_date("$Date: 2015/12/23 21:38:30 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "logins.nasl", "smtp_settings.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

 banner = ftp_recv_line(socket:soc);
 if (!banner) exit(1, "Cannot read FTP banner from port "+port+".");
 send(socket:soc, data:string("USER nessus", rand(), rand(), "\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!r)exit(0);
 
 send(socket:soc, data:string("PASS whatever\r\n"));
 r = recv_line(socket:soc, length:4096);
 if(!r) exit(0);
 close(soc);
 if("530-Account does not exist" >< r) security_warning(port);

