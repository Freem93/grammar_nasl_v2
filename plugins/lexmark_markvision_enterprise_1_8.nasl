#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66328);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/05/06 13:51:55 $");

  script_cve_id("CVE-2013-3055");
  script_bugtraq_id(59513);
  script_osvdb_id(92716);

  script_name(english:"Lexmark Markvision Enterprise Remote Command Execution");
  script_summary(english:"Checks version of Lexmark Markvision Enterprise");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server has a web application that is affected by a
remote command execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Lexmark Markvision installed on the remote host is
earlier than 1.8.0 and gets installed with a Groovy Shell (intended for
diagnostic purposes) that binds to TCP port 9789. This could allow
for commands to be executed by an unauthenticated, remote attacker.

Note that this plugin does not verify that Groovy Shell is listening and
instead only does a version check of Lexmark Markvision install."
  );
  # http://support.lexmark.com/index?page=content&id=TE530&locale=en&userlocale=EN_US
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db169a54");
  script_set_attribute(attribute:"solution", value:"Upgrade to Lexmark Markvision 1.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:lexmark:markvision");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("lexmark_markvision_enterprise_detect.nasl");
  script_require_keys("www/lexmark_markvision_enterprise");
  script_require_ports("Services/www", 9788);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:9788);

appname = "Lexmark Markvision Enterprise";

install = get_install_from_kb(appname:'lexmark_markvision_enterprise', port:port, exit_on_fail:TRUE);
version = install['ver'];

url = build_url(port:port, qs:install['dir']);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);

ver = split(version, sep:".", keep:FALSE);
for(i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (max_index(ver) < 2)
  exit(1, "Version information from server on " + port + " is not verbose enough to determine if host is vulnerable.");

if (
  ver[0] < 1 ||
  (ver[0] == 1 && ver[1] < 8)
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + version +
             '\n  Fixed version     : 1.8.0\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
