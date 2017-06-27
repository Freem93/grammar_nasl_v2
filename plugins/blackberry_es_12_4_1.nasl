#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91460);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/06/06 15:56:50 $");

  script_cve_id(
    "CVE-2016-1916",
    "CVE-2016-1917",
    "CVE-2016-1918",
    "CVE-2016-3126"
  );
  script_osvdb_id(
    137078,
    137079,
    137080,
    137081
  );

  script_name(english:"BlackBerry Enterprise Service (BES) Management Console 12.x < 12.4.1 Multiple XSS");
  script_summary(english:"Checks the version of BlackBerry Enterprise Service.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by multiple
cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the BlackBerry Enterprise
Service (BES) management console running on the remote host is prior
to 12.4.1. It is, therefore, affected by the following
vulnerabilities :

  - A cross-site scripting vulnerability exists due to
    improper validation of crafted admin policies. An
    authenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2016-1916)

  - Multiple unspecified cross-site scripting
    vulnerabilities exist due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2016-1917, CVE-2016-1918, CVE-2016-3126)");
  script_set_attribute(attribute:"see_also", value:"http://support.blackberry.com/kb/articleDetail?articleNumber=000038117");
  script_set_attribute(attribute:"see_also", value:"http://support.blackberry.com/kb/articleDetail?articleNumber=000038118");
  script_set_attribute(attribute:"see_also", value:"http://support.blackberry.com/kb/articleDetail?articleNumber=000038119");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BlackBerry Enterprise Service version 12.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:blackberry:blackberry_enterprise_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("blackberry_es_installed.nasl", "blackberry_es_detect.nbin");
  script_require_keys("installed_sw/BlackBerry Enterprise Service");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'BlackBerry Enterprise Service';

install = get_single_install(app_name:app, combined:TRUE, exit_if_unknown_ver:TRUE);

product = install['Product'];
version = install['version'];
path    = install['path'];

if (app >!< product)
  audit(AUDIT_NOT_INST, app);

port = install['port'];
if (!empty_or_null(port))
{
  if (empty_or_null(path)) path = "/";
  path = build_url2(port:port, qs:path);
}
else
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;
}

fix = "12.4.1";
if (version =~ "^12\." && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Product              : ' + product +
    '\n  Path                 : ' + path +
    '\n  Installed version    : ' + version +
    '\n  Fixed version        : ' + fix +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING, xss:TRUE);
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
