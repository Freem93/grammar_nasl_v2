#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90774);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_cve_id("CVE-2016-82012", "CVE-2016-82013");
  script_osvdb_id(136982, 136983);

  script_name(english:"Tenable Nessus 6.0.x < 6.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the Nessus version.");

  script_set_attribute(attribute:"synopsis",value:
"An application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"According to its self-reported version, the Tenable Nessus application
running on the remote host is 6.x prior to 6.6. It is, therefore,
affected by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input. An
    authenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-82012)

  - A denial of service vulnerability exists due to an
    external entity injection (XXE) flaw that is triggered
    during the parsing of XML data. An authenticated,
    remote attacker can exploit this, via specially
    crafted XML data, to exhaust system resources.
    (CVE-2016-82013)");
  script_set_attribute(attribute:"see_also",value:"https://www.tenable.com/security/tns-2016-08");
  script_set_attribute(attribute:"solution",value:
"Upgrade to Tenable Nessus version 6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/28");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("nessus_detect.nasl");
  script_require_ports("Services/www", 8834);
  script_require_keys("installed_sw/nessus");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = "nessus";
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:8834);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);

version = install['version'];

fix = '6.6';

#Affected versions:
# 6.0 < 6.6
if (version =~ '^6\\.' && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port: port, severity:SECURITY_WARNING, extra: report, xss:TRUE);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Nessus", port, version);
