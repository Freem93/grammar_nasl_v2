#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44426);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2009-3989");
  script_bugtraq_id(38025);
  script_osvdb_id(62149);

  script_name(english:"Bugzilla Directory Access Information Disclosure");
  script_summary(english:"Checks for a directory listing");

  script_set_attribute(attribute:"synopsis", value:
"A CGI hosted on the remote web server is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Bugzilla hosted on the remote web server allows an
unauthenticated, remote attacker to list the contents of directories
such as '/contrib/', which could contain sensitive information.");
  script_set_attribute(attribute:"see_also", value:"http://www.bugzilla.org/security/3.0.10/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Bugzilla version 3.5.3 / 3.4.5 / 3.2.6 / 3.0.11 or later
and make sure permissions are set accordingly.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("bugzilla_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/Bugzilla");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install["version"];
path = install["path"];

install_loc = build_url(port:port, qs:path);
url = install_loc + "contrib/";

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  "<title>Index of "+url >< res[2] ||
  "bugzilla-queue" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to verify the issue using the following URL :\n' +
      '\n' +
      '  ' + build_url(port:port, qs:url) + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
