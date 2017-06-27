#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(10503);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2014/05/26 16:30:03 $");

  script_cve_id("CVE-2000-0868");
  script_bugtraq_id(1658);
  script_osvdb_id(402);

  script_name(english:"Apache on SuSE Linux cgi-bin-sdb Request Script Source Disclosure");
  script_summary(english:"Checks for the presence of /cgi-bin-sdb/");

  script_set_attribute(attribute:"synopsis", value:"The remote service is vulnerable to information disclosure.");
  script_set_attribute(attribute:"description", value:
"The directory /cgi-bin-sdb is an Alias of /cgi-bin - most SuSE systems
are configured that way.

This setting allows an attacker to obtain the source code of the
installed CGI scripts on this host. This is dangerous as it gives an
attacker valuable information about the setup of this host, or perhaps
usernames and passwords if they are hard-coded into the CGI scripts.");
  script_set_attribute(attribute:"see_also", value:"http://archives.neohapsis.com/archives/linux/suse/2000-q3/0906.html");
  script_set_attribute(attribute:"solution", value:
"In httpd.conf, change the directive : 

  Alias /cgi-bin-sdb/ /usr/local/httpd/cgi-bin/ 

to 

  ScriptAlias /cgi-bin-sdb/ /usr/local/httpd/cgi-bin/");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2000/09/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2000-2014 Tenable Network Security, Inc.");
  script_family(english:"Web Servers");

  script_dependencie("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

  # First try : attempt to get printenv
u = string("/cgi-bin-sdb/printenv");
w = http_send_recv3(method:"GET", item:u, port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
r = strcat(w[0], w[1], '\r\n', w[2]);

if("/usr/bin/perl" >< r)
  	security_warning(port);
