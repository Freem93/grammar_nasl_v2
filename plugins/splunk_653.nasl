#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99235);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/28 13:38:34 $");

  script_cve_id("CVE-2017-5607");
  script_bugtraq_id(97265, 97286);
  script_osvdb_id(
    154700,
    154701,
    156028,
    156029,
    156030
 );
  script_xref(name:"IAVB", value:"2017-B-0048");

  script_name(english:"Splunk Enterprise < 5.0.18 / 6.0.14 / 6.1.13 / 6.2.13.1 / 6.3.10 / 6.4.6 / 6.5.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Splunk Enterprise.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk
Enterprise hosted on the remote web server is 5.0.x prior to 5.0.18,
6.0.x prior to 6.0.14, 6.1.x prior to 6.1.13, 6.2.x prior to 6.2.13.1,
6.3.x prior to 6.3.10, 6.4.x prior to 6.4.6, or 6.5.x prior to 6.5.3.
It is, therefore, affected by multiple vulnerabilities :

 -  An information disclosure vulnerability exists due to
    various system information being assigned to the global
    window property '$C' when a request is made to
    '/en-US/config?autoload=1'. An unauthenticated, remote
    attacker attacker can exploit this, via a specially
    crafted web page, to disclose sensitive information.
    (CVE-2017-5607)

  - A stored cross-site scripting (XSS) vulnerability exists
    in the web interface due to improper validation of
    unspecified input before returning to users. An
    authenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (VulnDB 154701)

  - Multiple cross-site scripting (XSS) vulnerabilities
    exist due to improper validation of user-supplied input.
    An unauthenticated, remote attacker can exploit these
    vulnerabilities, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. Note that these vulnerabilities only affect
    Splunk Enterprise 6.4.x prior to 6.4.7 and Splunk Light
    6.5.x prior to 6.5.3. (VulnDB 156028, VulnDB 156029,
    VulnDB 156030)");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAPZ3");
  script_set_attribute(attribute:"see_also", value:"https://www.splunk.com/view/SP-CAAAP2K");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Splunk Enterprise version 5.0.18 / 6.0.14 / 6.1.13 /
6.2.13.1 / 6.3.10 / 6.4.6 / 6.5.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("splunkd_detect.nasl", "splunk_web_detect.nasl");
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
license = install['License'];
if (isnull(license)) exit(1, "Unable to retrieve the Splunk license type.");

fix = FALSE;

install_url = build_url(qs:dir, port:port);

if (license == "Enterprise")
{
  # 5.0.x < 5.0.18
  if (ver =~ "^5\.0($|[^0-9])")
    fix = '5.0.18';

  # 6.0.x < 6.0.14
  else if (ver =~ "^6\.0($|[^0-9])")
    fix = '6.0.14';

  # 6.1.x < 6.1.13
  else if (ver =~ "^6\.1($|[^0-9])")
    fix = '6.1.13';

  # 6.2.x < 6.2.13.1
  else if (ver =~ "^6\.2($|[^0-9])")
    fix = '6.2.13.1';

  # 6.3.x < 6.3.10
  else if (ver =~ "^6\.3($|[^0-9])")
    fix = '6.3.10';

  # 6.4.x < 6.4.6
  else if (ver =~ "^6\.4($|[^0-9])")
    fix = '6.4.6';

  # 6.5.x < 6.5.3
  else if (ver =~ "^6\.5($|[^0-9])")
    fix = '6.5.3';
}

if (fix && ver_compare(ver:ver,fix:fix,strict:FALSE) < 0)
{
  order = make_list("URL", "Installed version", "Fixed version");
  report = make_array(
    order[0], install_url,
    order[1], ver + " " + license,
    order[2], fix + " " + license
  );
  report = report_items_str(report_items:report, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver + " " + license);
