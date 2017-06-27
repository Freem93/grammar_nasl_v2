#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93110);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_bugtraq_id(92603);
  script_osvdb_id(143401);

  script_name(english:"Splunk Enterprise < 5.0.16 / 6.0.12 / 6.1.11 / 6.2.10 / 6.3.6 / 6.4.3 or Splunk Light < 6.4.3 Cross-Site Redirection");
  script_summary(english:"Checks the version of Splunk Enterprise and Light.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Splunk
Enterprise hosted on the remote web server is 5.0.x prior to 5.0.16,
6.0.x prior to 6.0.12, 6.1.x prior to 6.1.11, 6.2.x prior to 6.2.10,
6.3.x prior to 6.3.6, or 6.4.x prior to 6.4.3; or else it is Splunk
Light version 6.4.x prior to 6.4.3. It is, therefore, affected by a
cross-site redirection vulnerability due to improper validation of
unspecified input before returning it to the user. An unauthenticated,
remote attacker can exploit this, by convincing a user to follow a
specially crafted URL, to redirect the user to an arbitrary website of
the attacker's choosing.");
  script_set_attribute(attribute:"see_also", value:"http://www.splunk.com/view/SP-CAAAPQ6");
  script_set_attribute(attribute:"solution", value:
"Upgrade Splunk Enterprise to version 5.0.16 / 6.0.12 / 6.1.11 /
6.2.10 / 6.3.6 / 6.4.3 or later, or Splunk Light to version 6.4.3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:splunk:splunk");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

note = NULL;
if (license == "Enterprise")
{
  # 5.0.x < 5.0.16
  if (ver =~ "^5\.0($|[^0-9])")
    fix = '5.0.16';

  # 6.0.x < 6.0.12
  else if (ver =~ "^6\.0($|[^0-9])")
    fix = '6.0.12';

  # 6.1.x < 6.1.11
  else if (ver =~ "^6\.1($|[^0-9])")
    fix = '6.1.11';

  # 6.2.x < 6.2.10
  else if (ver =~ "^6\.2($|[^0-9])")
    fix = '6.2.10';

  # 6.3.x < 6.3.6
  else if (ver =~ "^6\.3($|[^0-9])")
    fix = '6.3.6';

  # 6.4.x < 6.4.2
  else if (ver =~ "^6\.4($|[^0-9])")
    fix = '6.4.3';
}
else if (license == "Light")
{
  # any < 6.4.2
  fix = '6.4.3';
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
