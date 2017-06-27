#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80914);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/11 21:07:49 $");

  script_cve_id(
    "CVE-2014-6316",
    "CVE-2014-6387",
    "CVE-2014-7146",
    "CVE-2014-8553",
    "CVE-2014-8554",
    "CVE-2014-8598",
    "CVE-2014-8986",
    "CVE-2014-8987",
    "CVE-2014-8988",
    "CVE-2014-9089",
    "CVE-2014-9117",
    "CVE-2014-9269",
    "CVE-2014-9270",
    "CVE-2014-9271",
    "CVE-2014-9272",
    "CVE-2014-9279",
    "CVE-2014-9280",
    "CVE-2014-9281"
  );
  script_bugtraq_id(
    70856,
    70993,
    70996,
    71104,
    71321,
    71359,
    71361,
    71371,
    71372,
    71478
  );
  script_osvdb_id(
    115318,
    115319,
    115320,
    115506,
    115672
  );

  script_name(english:"MantisBT 1.2.x < 1.2.18 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mantis.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the MantisBT application hosted on
the remote web server is 1.2.x prior to 1.2.18. It is, therefore,
affected by the following vulnerabilities :

  - Multiple input-validation errors exist that could allow
    cross-site scripting attacks. (CVE-2014-7146,
    CVE-2014-8986, CVE-2014-8987, CVE-2014-9269,
    CVE-2014-9270, CVE-2014-9271, CVE-2014-9272,
    CVE-2014-9280, CVE-2014-9281)

  - Two unspecified errors exist that could allow SQL
    injection attacks. (CVE-2014-8554, CVE-2014-9089)

  - Three unspecified errors exist that could allow
    information disclosure attacks. (CVE-2014-8553,
    CVE-2014-8988, CVE-2014-9279)

  - An error exists in the file 'core/string_api.php' that
    could allow open redirect attacks. (CVE-2014-6316)

  - An error exists in the file 'gpc_api.php' that could
    allow an attacker to bypass authentication protections
    by using a password that starts with a NULL byte.
    (CVE-2014-6387)

  - An error exists in the 'XML Import/Export' plugin that
    could allow unauthorized attackers to upload XML files
    or obtain sensitive information. (CVE-2014-8598)

  - An error exists related to the CAPTCHA protection
    mechanism and the parameter 'public_key' that could
    allow security bypasses. (CVE-2014-9117)

Note that Nessus has not attempted to exploit this issue but has
instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.mantisbt.org/blog/?p=301");
  script_set_attribute(attribute:"see_also", value:"https://www.mantisbt.org/bugs/changelog_page.php?version_id=191");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 1.2.18 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MantisBT XmlImportExport Plugin PHP Code Injection Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

port = get_http_port(default:80, php:TRUE);

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port, exit_if_unknown_ver:TRUE);
install_url = build_url(port:port, qs:install['path']);
version = install['version'];

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Versions 1.2.x < 1.2.18 are vulnerable
if (ver[0] == 1 && ver[1] == 2 && ver[2] < 18)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 1.2.18\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
