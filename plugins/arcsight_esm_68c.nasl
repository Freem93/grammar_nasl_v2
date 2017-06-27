#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82848);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/20 20:49:17 $");

  script_cve_id("CVE-2014-7885");
  script_bugtraq_id(73073);
  script_osvdb_id(119490, 119697);
  script_xref(name:"CERT", value:"868948");
  script_xref(name:"HP", value:"HPSBGN03249");
  script_xref(name:"HP", value:"emr_na-c04562193");
  script_xref(name:"HP", value:"SSRT101697");

  script_name(english:"HP ArcSight ESM < 6.5c SP1 P1 / 6.8c Multiple Vulnerabilities");
  script_summary(english:"Checks the ArcSight ESM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A security management system installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of HP
ArcSight Enterprise Security Manager (ESM) installed on the remote
host is prior to 6.5.1.1845.0 (6.5c SP1 P1) or 6.8.0.1896 (6.8c). It
is, therefore, affected by multiple vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists due to
    a failure to validate input to tooltips before returning
    it to the user. A remote attacker can exploit this, via
    a specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2014-7885)

  - A cross-site request forgery (XSRF) vulnerability exists
    due to a failure to require multiple steps, explicit
    confirmation, or a unique token when performing certain
    sensitive actions. A remote attacker can exploit this by
    convincing a user to follow a specially crafted link,
    allowing the attacker to make changes to rules or
    resources on the system. (VulnDB 119697)");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04562193
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fe980fb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP ArcSight ESM 6.5.1.1845.0 (6.5c SP1 P1) / 6.8.0.1896
(6.8c) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_enterprise_security_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_arcsight_esm_installed.nbin");
  script_require_keys("installed_sw/HP ArcSight Enterprise Security Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "HP ArcSight Enterprise Security Manager";
port = 0;

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver = install['version'];
path = install['path'];

fix = '6.5.1.1845.0';
display_fix = '6.5.1.1845.0 (6.5c SP1 P1) / 6.8.0.1896 (6.8c)';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
