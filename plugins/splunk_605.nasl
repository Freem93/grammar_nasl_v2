#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76528);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/12 14:55:05 $");

  script_cve_id("CVE-2014-0224", "CVE-2014-3470");
  script_bugtraq_id(67898, 67899);
  script_osvdb_id(107729, 107731);
  script_xref(name:"CERT", value:"978508");

  script_name(english:"Splunk Enterprise 4.3.x / 5.0.x < 5.0.9 / 6.0.x < 6.0.5 / 6.1.x < 6.1.2 Multiple OpenSSL Vulnerabilities");
  script_summary(english:"Checks the version of Splunk Enterprise.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple OpenSSL-related vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the Splunk Enterprise hosted on the
remote web server is 4.3.x, 5.0.x prior to 5.0.9, 6.0.x prior to
6.0.5, or 6.1.x prior to 6.1.2. It is, therefore, affected by multiple
OpenSSL-related vulnerabilities :

  - An unspecified error exists that allows an attacker to
    cause usage of weak keying material, resulting in
    simplified man-in-the-middle attacks. (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    cipher suites that allow denial of service attacks. Note
    that this issue only affects OpenSSL TLS clients.
    (CVE-2014-3470)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAM2D");
  # http://blogs.splunk.com/2014/06/09/splunk-and-the-latest-openssl-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aacb6e20");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise 5.0.9 / 6.0.5 / 6.1.2 or later as
appropriate.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

license = install['License'];
if (isnull(license) || license != "Enterprise")
  exit(0, "The Splunk install at "+install_url+" is not the Enterprise variant.");

fix = FALSE;

if (ver =~ "^4\.3($|[^0-9])") fix = 'Upgrade to 5.0.9 / 6.0.5 / 6.1.2';
else if (ver =~ "^5\.0($|[^0-9])") fix = '5.0.9';
else if (ver =~ "^6\.0($|[^0-9])") fix = '6.0.5';
else if (ver =~ "^6\.1($|[^0-9])") fix = '6.1.2';

if (fix && ("Upgrade" >< fix || ver_compare(ver:ver, fix:fix, strict:FALSE) < 0))
{
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
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver);
