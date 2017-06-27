#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10556);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2001-0450");
 script_bugtraq_id(301);
 script_osvdb_id(455, 17755);

 script_name(english:"Broker FTP Multiple Command Arbitrary File/Directory Manipulation");
 script_summary(english:"Attempts to get the listing of the remote root dir");

 script_set_attribute(attribute:"synopsis", value:"The remote FTP server has a directory traversal vulnerability.");
 script_set_attribute(attribute:"description", value:
"Broker FTP appears to be running on the remote host. This version has
a directory traversal vulnerability that allows a remote attacker to
view and delete files outside of the FTP root directory.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Mar/26");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of Broker FTP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/03/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/11/24");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "Settings/ParanoidReport");
 script_exclude_keys("ftp/ncftpd", "ftp/msftpd");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("ftp_func.inc");
include("global_settings.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1, "Cannot connect to TCP port "+port+".");

 if(ftp_authenticate(socket:soc, user:"anonymous", pass:string("nessus@", get_host_name())))
{
 p = ftp_pasv(socket:soc);
 soc2 = open_sock_tcp(p, transport:get_port_transport(port));
 if(soc2)
 {
  s = string("LIST /\r\n");
  send(socket:soc, data:s);
  r = ftp_recv_line(socket:soc);
  if(egrep(pattern:"^150 ", string:r))
  {
      listing1 = ftp_recv_listing(socket:soc2);
  }
  close(soc2);
  r = ftp_recv_line(socket:soc);

  p = ftp_pasv(socket:soc);
  soc2 = open_sock_tcp(p, transport:get_port_transport(port));
  if ( ! soc2 ) exit(1, "Cannot connect to TCP port "+p+".");


  s = string("LIST C:\\\r\n");
  send(socket:soc, data:s);
  r = ftp_recv_line(socket:soc);
  if(egrep(pattern:"^150 ", string:r))
  {
      r = ftp_recv_listing(socket:soc2);
      if(r && ( listing1 != r ) )
      {
	if("No such file or directory" >< r)exit(0);
      w = string("It was possible to get the listing of the remote root\n",
"directory by issuing the command\n\n",
"LIST C:\\\n",
"Which displays :\n",
r, "\n");
  security_hole(port:port, extra:w);
     }
  }
 close(soc);
 close(soc2);
 }
}

