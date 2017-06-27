#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90313);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id("CVE-2016-1990", "CVE-2016-1991");
  script_osvdb_id(135910, 135911);
  script_xref(name:"HP", value:"HPSBGN03556");
  script_xref(name:"IAVA", value:"2016-A-0085");
  script_xref(name:"HP", value:"PSRT102039");
  script_xref(name:"HP", value:"emr_na-c05048452");

  script_name(english:"HP ArcSight ESM < 5.6 / 6.0 / 6.5c SP1 P2 / 6.8c Multiple Vulnerabilities");
  script_summary(english:"Checks the ArcSight ESM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A security management system installed on the remote host is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of HP
ArcSight Enterprise Security Manager (ESM) installed on the remote
host is prior to 5.6, 6.0, 6.5.1.1845.0 (6.5c SP1 P2), or 6.8.0.1896
(6.8c). It is, therefore, affected by multiple vulnerabilities :

  - An unspecified flaw exists that allows a local attacker
    to execute arbitrary commands. (CVE-2016-1990)

  - An unspecified flaw exists that allows an authenticated,
    remote attacker to upload arbitrary files.
    (CVE-2016-1991)");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05048452
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0aab6435");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP ArcSight ESM version 5.6 / 6.0 / 6.5.1.1845.0 (6.5c SP1
P2), or 6.8.0.1896 (6.8c) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_enterprise_security_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("hp_arcsight_esm_installed.nbin");
  script_require_keys("installed_sw/HP ArcSight Enterprise Security Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "HP ArcSight Enterprise Security Manager";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver = install['version'];
path = install['path'];

# 6.5c SP1 P1 = 6.5.1.1845.0
# 6.8c        = 6.8.0.1896

fix = NULL;

# 5.x < 5.6
if (ver =~ "^5\.[0-5]\.")
  fix = "5.6";

# 6.5.x < 6.5c SP1 P2
if (ver =~ "^6\.5\." &&
    ver_compare(ver:ver, fix:"6.5.1.1845.0", strict:FALSE) <= 0 )
  fix = "6.5c SP1 P2";

# 6.6?.x < 6.8c P1
if (ver =~ "^6\.8\." &&
    ver_compare(ver:ver, fix:"6.8.0.1896", strict:FALSE) <= 0 )
  fix = "6.8c P1";

if (ver =~ "^6\.9\.0(\.|$)")
  fix = "6.9.1";


if (fix)
{
  items = make_array("Path", path,
                     "Installed version", ver,
                     "Fixed version", fix
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
  exit(0);

}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);
