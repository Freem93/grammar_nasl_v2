#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70070);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/20 14:29:55 $");

  script_cve_id("CVE-2010-2644");
  script_bugtraq_id(45585);
  script_osvdb_id(70020);

  script_name(english:"IBM WebSphere Service Registry and Repository 7.0 < 7.0.0 FP1 Authentication Bypass");
  script_summary(english:"Checks version of WebSphere Service Registry and Repository");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application installed that is affected by an
authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM WebSphere Service Registry and Repository is 7.0
earlier than Fix Pack 1.  Such versions are potentially affected by a
flaw in the implementation of access controls in the EJB interface.  A
remote, unauthenticated attacker could exploit this flaw in order to
bypass access controls.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24026132");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Service Registry and Repository 7.0.0 Fix
Pack 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/23");

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

if (version =~ '^7\\.0\\.' && ver_compare(ver:version, fix:'7.0.0.1') < 0)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);

