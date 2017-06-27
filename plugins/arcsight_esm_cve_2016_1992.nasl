#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90266);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/29 19:06:02 $");

  script_cve_id("CVE-2016-1992");
  script_osvdb_id(135966);
  script_xref(name:"HP", value:"emr_na-c05048753");
  script_xref(name:"IAVA", value:"2016-A-0085");
  script_xref(name:"HP", value:"SSRT110019");
  script_xref(name:"HP", value:"HPSBGN03558");

  script_name(english:"HP ArcSight ESM < 6.8c Information Disclosure");
  script_summary(english:"Checks the ArcSight ESM version number.");

  script_set_attribute(attribute:"synopsis", value:
"A security management system installed on the remote host is affected
by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of HP
ArcSight Enterprise Security Manager (ESM) installed on the remote
host is prior to 6.8.0.1896 (6.8c). It is, therefore, affected by an
unspecified flaw that allows an authenticated, remote attacker to
disclose sensitive information.");
  # https://h20564.www2.hpe.com/portal/site/hpsc/public/kb/docDisplay?docId=emr_na-c05048753
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?113a0d48");
  # https://packetstormsecurity.com/files/136263/HP-Security-Bulletin-HPSBGN03558-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df41be50");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2016/Mar/126");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP ArcSight ESM version 6.8.0.1896 (6.8c) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/15");
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
port = 0;

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver = install['version'];
path = install['path'];

fix = '6.8.0.1896';
display_fix = '6.8.0.1896 (6.8c)';

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, ver);

report =
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + display_fix + '\n';
security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
