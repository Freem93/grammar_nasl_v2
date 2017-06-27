#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10538);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2014/05/26 00:33:32 $");

 script_cve_id("CVE-2000-1077");
 script_bugtraq_id(1848);
 script_osvdb_id(437);

 script_name(english:"iPlanet Web Server shtml File Handling Remote Overflow");
 script_summary(english:"Web server buffer overflow");

 script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to make the remote iPlanet web server execute arbitrary
code when requesting a too long .shtml file (with a name longer than
800 chars and containing computer code).

An attacker may use this flaw to gain a shell on this host");
 script_set_attribute(attribute:"solution", value:"There is no known solution at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/26");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/10/26");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport", "www/iplanet");
 script_require_ports("Services/www",80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

soc = http_open_socket(port);
if(soc)
{
  banner = get_http_banner(port:port);
  if(egrep(pattern:"^Server:.*Netscape-Enterprise", string:banner))
  {
    res = http_send_recv3(method:"GET", item:"/XXX.shtml", port:port);
    if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

    res2 = http_send_recv3(method:"GET", item:string("/", crap(800), ".shtml"), port:port);
    if (isnull(res2)) security_hole(port);
  }
}
