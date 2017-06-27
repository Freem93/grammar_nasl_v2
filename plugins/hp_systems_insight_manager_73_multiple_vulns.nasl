#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72964);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id(
    "CVE-2013-0646",
    "CVE-2013-0650",
    "CVE-2013-1371",
    "CVE-2013-1375",
    "CVE-2013-1378",
    "CVE-2013-1379",
    "CVE-2013-1380",
    "CVE-2013-2555"
  );
  script_bugtraq_id(
    58396,
    58436,
    58438,
    58439,
    58440,
    58947,
    58949,
    58951
  );
  script_osvdb_id(
    91158,
    91159,
    91160,
    91161,
    91203,
    92141,
    92142,
    92143
  );
  script_xref(name:"HP", value:"emr_na-c040307378");
  script_xref(name:"HP", value:"HPSBMU02948");
  script_xref(name:"HP", value:"SSRT100986");

  script_name(english:"HP Systems Insight Manager < 7.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Systems Insight Manager.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains software that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP Systems Insight Manager installed on the remote
Windows host is affected by vulnerabilities in the included Flash
components.");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04039150-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24855185");
  # http://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04030737
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7716684f");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP Systems Insight Manager 7.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:systems_insight_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_systems_insight_manager_installed.nasl");
  script_require_keys("installed_sw/HP Systems Insight Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app_name = "HP Systems Insight Manager";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

install = get_single_install(app_name:app_name);
path = install['path'];
version = install['version'];

if (version =~ '^(([A-Z]\\.)?0[0-6]\\.|([A-C]\\.)?07\\.0[0-2]\\.[0-9\\.]+)')
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : C.07.03.00.00\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
