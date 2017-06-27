#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88904);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_cve_id("CVE-2016-82000");
  script_osvdb_id(134521);

  script_name(english:"Tenable Nessus < 6.5.5 Host Details Scan Results XSS");
  script_summary(english:"Checks the Nessus version.");

  script_set_attribute(attribute:"synopsis",value:
"The remote Nessus installation is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description",value:
"According to its version, the Tenable Nessus application running on
the remote host is prior to 6.5.5. It is, therefore, affected by a
cross-site scripting (XSS) vulnerability in the Host Details section
due to improper sanitization of user-supplied input. An
unauthenticated, remote attacker can exploit this, via importing a
malicious file or by scanning a malicious host that returns JavaScript
instead of a hostname, to introduce and store JavaScript in the scan
results, which can be later executed in the context of the user
viewing the results.");
  script_set_attribute(attribute:"see_also",value:"https://www.tenable.com/security/tns-2016-02");
  script_set_attribute(attribute:"solution",value:
"Upgrade to Tenable Nessus version 6.5.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/02/15");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/23");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:tenable:nessus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

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

ver_ui = install['Nessus UI Version'];
if (ver_compare(ver:ver_ui, fix:'2.0.0', strict:FALSE) < 0)
  audit(AUDIT_LISTEN_NOT_VULN, "Nessus", port, ver_ui);

version = install['version'];

fix = '6.5.5';

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port: port, severity:SECURITY_NOTE, extra: report, xss:TRUE);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Nessus", port, version);
