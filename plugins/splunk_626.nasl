#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85962);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/24 04:42:09 $");

  script_osvdb_id(127461);

  script_name(english:"Splunk Enterprise 6.2.x < 6.2.6 / Splunk Light 6.2.x < 6.2.6 Splunk Web XSS");
  script_summary(english:"Checks the version of Splunk Enterprise and Light.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of Splunk hosted on the
remote web server is Splunk Enterprise 6.2.x prior to 6.2.6 or Splunk
Light 6.2.x prior to 6.2.6. It is, therefore, affected by a cross-site
scripting vulnerability in the Splunk Web component due to improper
validation of user-supplied input. A remote attacker can exploit this,
via a specially crafted request, to execute arbitrary script code in a
user's browser session.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAPAM");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise 6.2.6 / Splunk Light 6.2.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
fix = FALSE;

install_url = build_url(qs:dir, port:port);

# 6.2.x < 6.2.6
if (ver =~ "^6\.2($|[^0-9])")
  fix = '6.2.6';

if (fix && ver_compare(ver:ver,fix:fix,strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
