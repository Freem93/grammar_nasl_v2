#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19415);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2005-1527");
  script_bugtraq_id(14525);
  script_osvdb_id(18696);

  script_name(english:"AWStats Referrer Header Arbitrary Command Execution");
  script_summary(english:"Checks for referrer arbitrary command execution vulnerability in AWStats");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that allows execution of
arbitrary commands.");
  script_set_attribute(attribute:"description", value:
"The remote host is running AWStats, an open source web analytics tool used for
analyzing data from internet services such as web, streaming, media, mail and FTP
servers.

The version of AWStats installed on the remote host collects data
about the web referrers and uses them without proper sanitation in an
eval() statement.  Using specially crafted referrer data, an attacker
can cause arbitrary Perl code to be executed on the remote host within
the context of the affected application once the stats page has been
regenerated and when a user visits the referer statistics page.

Note that successful exploitation requires that at least one URLPlugin
is enabled.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e529878e");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Aug/237");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Aug/369");
  script_set_attribute(attribute:"solution", value:"Upgrade to AWStats 6.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:laurent_destailleur:awstats");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

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

ver = NULL;
install = get_install_from_kb(appname:'AWStats', port:port);
if (isnull(install)) exit(0, "The 'www/"+port+"/AWStats' KB item is missing.");
ver = install['ver'];

if (ver && "unknown" >< ver) exit(1, "unknown version.");

# Check the version number.
  if (ver && ver =~ "^([0-5]\.|6\.[0-4]^[0-9]?)")
  {
    security_warning(port);
    exit(0);
  }
