#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77856);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/13 21:07:13 $");

  script_cve_id("CVE-2014-2975");
  script_bugtraq_id(68923);
  script_osvdb_id(109604);
  script_xref(name:"CERT", value:"867980");

  script_name(english:"Silver Peak VX < 6.2.4 XSS");
  script_summary(english:"Checks the Silver Peak VX version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by a
cross-site scripting (XSS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Silver Peak VX install hosted on the remote web server is affected
by a cross-site scripting (XSS) vulnerability in the 'user_id'
parameter of the '/php/user_account.php' script. An attacker can
leverage this issue to inject arbitrary HTML and script code into a
user's browser to be executed within the security context of the
affected site.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 6.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:silver_peak:vx");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("silver_peak_vx_detect.nbin");
  script_require_keys("installed_sw/Silver Peak VX", "www/PHP");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'Silver Peak VX';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, embedded:TRUE, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

dir = install['path'];
version = install['version'];
install_url = build_url(qs:dir, port:port);

fix = "6.2.4";
ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] < 6) ||
  (ver[0] == 6 && ver[1] < 2) ||
  (ver[0] == 6 && ver[1] == 2 && ver[2] < 4)
)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : ' +fix+ '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
