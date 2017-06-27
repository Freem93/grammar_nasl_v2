#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94932);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/06 16:27:35 $");

  script_cve_id(
    "CVE-2016-5636",
    "CVE-2016-5699",
    "CVE-2016-0772"
  );
  script_bugtraq_id(
    91225,
    91226,
    91247
  );
  script_osvdb_id(
    115884,
    140038,
    140125,
    147171
  );

  script_name(english:"Splunk Enterprise < 5.0.17 / 6.0.13 / 6.1.12 / 6.2.12 / 6.3.8 / 6.4.4 or Splunk Light < 6.5.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Splunk Enterprise and Light.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk
Enterprise hosted on the remote web server is 5.0.x prior to 5.0.17,
6.0.x prior to 6.0.13, 6.1.x prior to 6.1.12, 6.2.x prior to 6.2.12,
6.3.x prior to 6.3.8, or 6.4.x prior to 6.4.4; or else it is Splunk
Light prior to 6.5.0. It is, therefore, affected by multiple
vulnerabilities :

  - A heap buffer overflow condition exists in Python,
    specifically in the get_data() function within file
    Modules/zipimport.c, due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via negative data size values, to
    cause a denial of service condition or the possible
    execution of arbitrary code. (CVE-2016-5636)

  - A CRLF injection vulnerability exists in Python,
    specifically in the HTTPConnection.putheader() function
    within file Modules/zipimport.c. An unauthenticated,
    remote attacker can exploit this to inject arbitrary
    HTTP headers via CRLF sequences in a URL, allowing
    cross-site scripting (XSS) and other attacks.
    (CVE-2016-5699)

  - A flaw exists in Python within the smtplib library due
    to a failure to properly raise exceptions when smtp
    servers are able to negotiate starttls but fail to
    respond properly. A man-in-the-middle attacker can
    exploit this issue to bypass TLS protections via a
    'StartTLS stripping attack.' (CVE-2016-0772)

  - An HTTP request injection vulnerability exists in Splunk
    that permits leakage of authentication tokens. An
    unauthenticated, remote attacker can exploit this to
    access the Splunk REST API with the same rights as the
    user. (VulnDB 147171)

Note that the Python vulnerabilities stated above do not affect the
Splunk Enterprise 6.4.x versions, and the HTTP request injection
vulnerability does not affect the Splunk Light versions.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAPSR");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to version 5.0.17 / 6.0.13 / 6.1.12 /
6.2.12 / 6.3.8 / 6.4.4 or later, or Splunk Light to version 6.5.0 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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
fix = FALSE;

install_url = build_url(qs:dir, port:port);

if (license == "Enterprise")
{
  # 5.0.x < 5.0.17
  if (ver =~ "^5\.0($|[^0-9])")
    fix = '5.0.17';

  # 6.0.x < 6.0.13
  else if (ver =~ "^6\.0($|[^0-9])")
    fix = '6.0.13';

  # 6.1.x < 6.1.12
  else if (ver =~ "^6\.1($|[^0-9])")
    fix = '6.1.12';

  # 6.2.x < 6.2.12
  else if (ver =~ "^6\.2($|[^0-9])")
    fix = '6.2.12';

  # 6.3.x < 6.3.8
  else if (ver =~ "^6\.3($|[^0-9])")
    fix = '6.3.8';

  # 6.4.x < 6.4.4
  else if (ver =~ "^6\.4($|[^0-9])")
    fix = '6.4.4';
}
else if (license == "Light")
{
  # any < 6.5.0
  fix = '6.5.0';
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

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, ver + " " + license);
