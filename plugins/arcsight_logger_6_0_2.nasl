#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85988);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 14:21:28 $");

  script_cve_id(
    "CVE-2015-2136",
    "CVE-2015-6029",
    "CVE-2015-6030"
  );
  script_bugtraq_id(
    77128,
    76732
  );
  script_osvdb_id(
    126710,
    129043,
    129044
  );
  script_xref(name:"HP", value:"HPSBMU03392");
  script_xref(name:"IAVA", value:"2015-A-0280");
  script_xref(name:"HP", value:"HPSBGN03429");
  script_xref(name:"HP", value:"HPSBGN03430");
  script_xref(name:"HP", value:"SSRT101904");
  script_xref(name:"HP", value:"SSRT101901");
  script_xref(name:"HP", value:"SSRT102157");
  script_xref(name:"HP", value:"emr_na-c04762372");
  script_xref(name:"HP", value:"emr_na-c04872416");
  script_xref(name:"HP", value:"emr_na-c04863612");
  script_xref(name:"CERT", value:"842252");

  script_name(english:"HP ArcSight Logger < 6.0 P2 Multiple Vulnerabilities");
  script_summary(english:"Checks the ArcSight Logger version number.");

  script_set_attribute(attribute:"synopsis", value:
"A log collection and management system installed on the remote host is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of HP
ArcSight Logger installed on the remote host is prior to 6.0 P2. It
is, therefore, affected by multiple vulnerabilities :

  - An authorization bypass vulnerability exists that allows
    an authenticated, remote attacker to bypass
    authorization checks and perform unauthorized actions.
    (CVE-2015-2136)

  - A security bypass vulnerability exists in the SOAP
    interface due to a failure to properly log and lockout
    failed login attempts. A remote attacker can exploit
    this to perform a brute-force attack. (CVE-2015-6029)

  - A file command handling local privilege escalation
    vulnerability exists due to files owned by the arcsight
    user being executed with root privileges. A local
    attacker can exploit this to run commands to gain
    elevated privileges. (CVE-2015-6030)");
  # http://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04762372
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?504b5092");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04872416
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f4fd592");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04863612
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af86bfaf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP ArcSight Logger 6.0 P2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:arcsight_logger");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

fix = '6.0.0.7334.2';
display_fix = '6.0.0.7334.2 (6.0 P2)';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + display_fix + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
