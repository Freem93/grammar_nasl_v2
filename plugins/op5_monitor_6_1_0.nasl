#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67008);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/28 00:56:49 $");

  script_bugtraq_id(59880);
  script_osvdb_id(93416, 93417, 93418, 93419, 93420);

  script_name(english:"op5 Monitor < 6.1.0 Information Disclosure and Security Bypass Vulnerabilities");
  script_summary(english:"Checks the version of op5 Monitor");

  script_set_attribute(attribute:"synopsis", value:
"A PHP application hosted on the remote web server is affected by
information disclosure and security bypass vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of op5 Monitor hosted on the remote web server is earlier
than 6.1.0.  It is, therefore, affected by the following information
disclosure and security bypass vulnerabilities:

  - Log files can be accessed without authentication, which
    may contain sensitive information. (Bug 6599)

  - A flaw exists relating to the Ninja component that may
    lead to unauthorized disclosure of sensitive
    information when handling group rights, group hosts or
    when accessing the Servicegroup summary. This flaw
    reportedly affects op5 6.x < 6.1.0. (Bug 6657)

  - A flaw exists in the Nacoma component that is triggered
    during handling of host permissions. This flaw
    reportedly affects op5 6.x < 6.1.0. (Bug 6667)

  - A flaw exists in the Ninja component that may lead to
    disclosure of hostnames.  This flaw reportedly affects
    op5 6.x < 6.1.0. (Bug 6779)

  - Limited view users can see comments of other servers.
    This flaw reportedly affects op5 6.x < 6.1.0. (Bug 6929)");
  script_set_attribute(attribute:"see_also", value:"https://bugs.op5.com/changelog_page.php?project_id=3");
  script_set_attribute(attribute:"see_also", value:"https://bugs.op5.com/view.php?id=6599");
  script_set_attribute(attribute:"see_also", value:"https://bugs.op5.com/view.php?id=6657");
  script_set_attribute(attribute:"see_also", value:"https://bugs.op5.com/view.php?id=6667");
  script_set_attribute(attribute:"see_also", value:"https://bugs.op5.com/view.php?id=6779");
  script_set_attribute(attribute:"see_also", value:"https://bugs.op5.com/view.php?id=6929");
  script_set_attribute(attribute:"solution", value:"Upgrade op5 Monitor to version 6.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/27");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:op5:monitor");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("op5_monitor_detect.nasl");
  script_require_keys("www/op5_monitor");
  script_require_ports("Services/www", 443);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

# Get details of the op5 Portal install.
port = get_http_port(default:443);

install = get_install_from_kb(appname:"op5_monitor", port:port, exit_on_fail:TRUE);
dir = install["dir"];
version = install["ver"];

url = build_url(port:port, qs:dir + "/");

appname = "op5 Monitor";
fix = '6.1.0';

# If we couldn't detect the version, we can't determine if the remote
# instance is vulnerable.
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_SERVER_VER, appname, port);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Op5 < 6.1.0
if (
  ver[0] < 6 ||
  (ver[0] == 6 && ver[1] < 1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
