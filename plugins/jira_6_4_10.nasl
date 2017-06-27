#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87218);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/23 14:38:50 $");

  script_cve_id("CVE-2015-2808");
  script_bugtraq_id(73684);
  script_osvdb_id(117855);

  script_name(english:"Atlassian JIRA < 6.4.10 / 7.0.0-OD-02 MitM Plaintext Disclosure (Bar Mitzvah)");
  script_summary(english:"Checks the version of JIRA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially
affected by a security feature bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the instance of
Atlassian JIRA hosted on the remote web server is prior to 6.4.10 or
7.0.0-OD-02. It is, therefore, potentially affected by a security
feature bypass vulnerability, known as Bar Mitzvah, due to improper
combination of state data with key data by the RC4 cipher algorithm
during the initialization phase. A man-in-the-middle attacker can
exploit this, via a brute-force attack using LSB values, to decrypt
the traffic.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://www.blackhat.com/docs/asia-15/materials/asia-15-Mantin-Bar-Mitzvah-Attack-Breaking-SSL-With-13-Year-Old-RC4-Weakness-wp.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bbf45ac");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian JIRA version 6.4.10 / 7.0.0-OD-02 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "Atlassian JIRA";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app_name,
  port     : port,
  exit_if_unknown_ver : TRUE
);

# Prevent potential false positives.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = install['path'];
ver = install['version'];

url = build_url(port:port, qs:dir);

fix = NULL;

# Match versions 7.x.x - 7.0.0-OD-01
if (ver =~ "^(7\.0\.0|7\.0\.0-OD-(0[01]))$")
  fix = "7.0.0-OD-02";

# Match versions 1.x - 6.4.9
if (ver =~ "^([0-6]\.[0-4]|[0-5]\.[0-9]|[0-5]\.[0-9][0-9]|[0-5]\.[0-9][0-9]\.[0-9]|[0-6]\.[0-3]\.[1-9][0-9]|[0-6]\.[0-4]\.[0-9])$")
  fix = "6.4.10";

if (!isnull(fix))
{
  if (report_verbosity > 0)
  { 
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + "6.4.10 / 7.0.0-OD-02" +
      '\n';

       security_note(port:port, extra:report);
     }
     else security_note(port:port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, ver);
