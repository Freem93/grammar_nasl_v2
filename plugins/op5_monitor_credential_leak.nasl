#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57579);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/02/08 22:04:49 $");

  script_cve_id("CVE-2012-0623");
  script_bugtraq_id(64608);
  script_osvdb_id(78067, 79945);

  script_name(english:"op5 Monitor Credential Leak");
  script_summary(english:"Checks the version of op5 Monitor");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application hosted on the remote web server discloses
credentials in error messages.");
  script_set_attribute(attribute:"description", value:
"The version of op5 Monitor hosted on the remote web server contains
an information disclosure vulnerability.  In the default
configuration, detailed error messages are enabled.  An authenticated
user, upon triggering an error, will be presented with sensitive data
including database credentials, the current user's hashed password,
and SQL statements.

Note that the versions affected by this vulnerability are also
affected by CVE-2012-0264, which is an improper session handling
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24b0cd28");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcd924ab");

  script_set_attribute(attribute:"solution", value:"Upgrade op5 Monitor to version 5.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/17");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:op5:monitor");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("op5_monitor_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/op5_monitor");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("webapp_func.inc");

# Get details of the op5 Portal install.
port = get_http_port(default:443);

install = get_install_from_kb(appname:"op5_monitor", port:port, exit_on_fail:TRUE);
dir = install["dir"];
version = install["ver"];
url = build_url(port:port, qs:dir + "/");

# If we couldn't detect the version, we can't determine if the remote
# instance is vulnerable.
if (version == UNKNOWN_VER)
  exit(0, "The version of op5 Monitor at " + url + " is unknown.");

# Check if the remote instance is vulnerable.
if (version != "5.3.5" && version != "5.4.0" && version != "5.4.2")
  exit(0, "The op5 Monitor " + version + " install at " + url + " is not affected.");

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.5.0' +
    '\n';
}
security_warning(port:port, extra:report);
