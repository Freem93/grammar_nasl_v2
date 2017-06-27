#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71466);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id("CVE-2013-6721");
  script_bugtraq_id(64301);
  script_osvdb_id(101070);

  script_name(english:"IBM WebSphere Service Registry and Repository 7.5 < 7.5.0 FP4 Script Injection");
  script_summary(english:"Checks version of WebSphere Service Registry and Repository");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Service Registry and Repository is 7.5
earlier than Fix Pack 4.  Such versions are potentially vulnerable to a
script injection attack in the WebSphere Service Registry and Repository
Widgets.  By tricking an authenticated user into opening a specially
crafted link, a remote attacker can execute script code in the user's
browser.");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_websphere_service_registry_and_repository_script_injection_vulnerability_cve_2013_6721?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8e58978");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21659623");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Service Registry and Repository 7.5.0 Fix Pack
4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_service_registry_and_repository");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_service_registry_repository_installed.nasl");
  script_require_keys("installed_sw/IBM WebSphere Service Registry and Repository");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'IBM WebSphere Service Registry and Repository';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
path = install['path'];
version = install['version'];

if (version =~ '^7\\.5\\.' && ver_compare(ver:version, fix:'7.5.0.4') < 0)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.5.0.4\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

