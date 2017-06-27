#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95924);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/20 14:45:31 $");

  script_cve_id("CVE-2016-8009");
  script_osvdb_id(148314);
  script_xref(name:"MCAFEE-SB", value:"SB10175");

  script_name(english:"McAfee Application Control 6.x < 6.2.0.567 / 7.0.x < 7.0.1.275 Unauthorized IOCTL Use Local Privilege Escalation (SB10175)");
  script_summary(english:"Checks the version of McAfee Application Control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a security application installed that is affected
by a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee Application Control (MAC) installed on the
remote Windows host is 6.x prior to 6.2.0 build 567 or 7.0.x prior to
7.0.1 build 275. It is, therefore, affected by a local privilege
escalation vulnerability due to the unauthorized use of IOCTL. A local
attacker can exploit this to gain elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10175");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee Application Control version 6.2.0.567 / 7.0.1.275 or
later as referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:application_control");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_app_ctl_installed.nbin");
  script_require_keys("installed_sw/McAfee Application Control");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = 'McAfee Application Control';
get_install_count(app_name:app, exit_if_zero:TRUE);

install = get_single_install(
  app_name : app,
  exit_if_unknown_ver : TRUE
);

path = install['path'];
version = install['version'];

fix = NULL;

if (version =~ "^6\.[012]\." && (ver_compare(ver:version, fix:"6.2.0.567", strict:FALSE) < 0))
  fix = "6.2.0.567";
else if (version =~ "^7\.0\." && (ver_compare(ver:version, fix:"7.0.1.275", strict:FALSE) < 0))
  fix = "7.0.1.275";

port = get_kb_item("SMB/transport");
if (! port)
  port = 445;

if (fix)
{
  report =
    '\n  Installed path    : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix + '\n';

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
