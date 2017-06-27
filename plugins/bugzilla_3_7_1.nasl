#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47748);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/09/22 17:06:55 $");

  script_bugtraq_id(41397);
  script_name(english:"Bugzilla 3.7/3.7.1 Information Disclosure");
  script_summary(english:"Checks Bugzilla version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that suffers from an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Bugzilla installed on the
remote host fails to restrict access to bugs created with inbound
email interface (email_in.pl) or with 'Bug.create' method in the
WebServices interface to 'mandatory' or 'Default' groups. This could
allow bug information to become publicly available instead of being
restricted to certain groups.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=574892");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.7.1/" );
  script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 3.7.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
dir = install["path"];
version = install["version"];

install_loc = build_url(port:port, qs:dir + "/query.cgi");

if (version =~ "^3.7(\.[01])?$")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed Version : ' + version +
      '\n  Fixed Version     : 3.7.2' +
      '\n  URL               : ' + install_loc;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
