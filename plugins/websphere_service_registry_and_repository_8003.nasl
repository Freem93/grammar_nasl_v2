#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80858);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/16 14:42:22 $");

  script_cve_id(
    "CVE-2014-6132",
    "CVE-2014-6153",
    "CVE-2014-6155",
    "CVE-2014-6178",
    "CVE-2014-6179",
    "CVE-2014-6186",
    "CVE-2014-6187",
    "CVE-2014-6188"
  );
  script_bugtraq_id(
    71897,
    71899,
    71900,
    71901,
    71905,
    71906,
    71907,
    71908
  );
  script_osvdb_id(
    116099,
    116100,
    116101,
    116102,
    116103,
    116104,
    116105,
    116106
  );
  script_xref(name:"IAVB", value:"2015-B-0003");

  script_name(english:"IBM WebSphere Service Registry and Repository 8.0 < 8.0.0.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of WebSphere Service Registry and Repository.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Service Registry and Repository (WSRR) is
version 8.0 prior to 8.0.0.3. It is therefore, affected by multiple
vulnerabilities :

  - An unspecified DOM based cross-site scripting (XSS)
    vulnerability in the WSRR web UI. (CVE-2014-6132)

  - WSSR web interface issues a cookie that is not declared
    SSL only. (CVE-2014-6153)

  - An unspecified path traversal vulnerability in the
    SERVICEREGISTRY UI. (CVE-2014-6155)

  - An unspecified script injection vulnerability in WSSR
    widgets. (CVE-2014-6178)

  - An unspecified DOM based cross-site scripting (XSS)
    vulnerability in the WSRR web UI. (CVE-2014-6179)

  - Improper enforcement of object access control
    restrictions. (CVE-2014-6186)

  - An unspecified cross-site request forgery (XSRF)
    vulnerability. (CVE-2014-6187)

  - Unspecified cross-site scripting (XSS) vulnerabilities.
    (CVE-2014-6188)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21693387");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Service Registry and Repository Fix Pack
8.0.0.3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_service_registry_and_repository");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_service_registry_repository_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere Service Registry and Repository");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'IBM WebSphere Service Registry and Repository';
fix = '8.0.0.3';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path = install['path'];
version = install['version'];

if (version =~ '^8\\.0\\.' && ver_compare(ver:version, fix:fix) < 0)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  set_kb_item(name:"www/0/XSRF", value:TRUE);
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

