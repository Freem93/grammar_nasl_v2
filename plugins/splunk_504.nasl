#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69284);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/06/23 19:48:37 $");

  script_bugtraq_id(61537);
  script_osvdb_id(95870);

  script_name(english:"Splunk < 5.0.4 X-FRAME-OPTIONS Clickjacking Vulnerability");
  script_summary(english:"Checks the version of Splunk.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains an application that is affected by a
clickjacking Vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version number, the Splunk Web hosted on the remote
web server is affected by a clickjacking vulnerability due to a
failure to use the X-FRAME-OPTIONS header. This allows an attacker to
embed elements such as links or buttons into frames on an externally
hosted, attacker-controlled site, resulting in unsuspecting users
performing unintended actions.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAH32");
  script_set_attribute(attribute:"see_also", value:"http://docs.splunk.com/Documentation/Splunk/latest/ReleaseNotes/5.0.4");
  script_set_attribute(attribute:"solution", value:"Upgrade to Splunk 5.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl","splunk_web_detect.nasl");
  script_require_ports("Services/www", 8089, 8000);
  script_require_keys("installed_sw/Splunk");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "Splunk";

get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8000, embedded:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
ver = install['version'];

install_url = build_url(qs:dir, port:port);

if (ver_compare(ver:ver,fix:"5.0.4",strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +ver+
      '\n  Fixed version     : 5.0.4\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
