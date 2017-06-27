#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86419);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/08/26 14:54:43 $");

  script_cve_id("CVE-2015-5441");
  script_osvdb_id(128253);
  script_xref(name:"HP", value:"HPSBGN03507");
  script_xref(name:"HP", value:"SSRT102181");
  script_xref(name:"HP", value:"emr_na-c04797406");

  script_name(english:"HP ArcSight Logger < 6.1 Management Center XSS");
  script_summary(english:"Checks the version of HP ArcSight Logger.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
reflected cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of HP ArcSight logger installed that is
prior to 6.1. It is, therefore, affected by a reflected cross-site
scripting vulnerability in the Management Center due to improper
validation of user-supplied input. A remote attacker can exploit this,
via a specially crafted request, to execute arbitrary script code in a
user's browser session.");
  # http://h20566.www2.hpe.com/hpsc/doc/public/display?calledBy=&docId=emr_na-c04797406
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?d9ac9186");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP ArcSight Logger version 6.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/16");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:hp:arcsight_logger");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("arcsight_logger_installed_linux.nasl");
  script_require_keys("installed_sw/ArcSight Logger");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_internals.inc");
include("install_func.inc");

app = "ArcSight Logger";
port = 0;

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver = install['version'];
path = install['path'];
display_ver = install['display_version'];

fix = '6.1';
display_fix = '6.1';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);

set_kb_item(name:"www/0/XSS", value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
