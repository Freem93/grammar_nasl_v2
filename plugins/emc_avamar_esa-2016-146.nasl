#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96956);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/07 14:52:09 $");

  script_cve_id("CVE-2016-8214");
  script_bugtraq_id(95719);
  script_osvdb_id(150744);
  script_xref(name:"IAVB", value:"2017-B-0009");

  script_name(english:"EMC Avamar ADS / AVE < 7.3.0 Hotfix 268253 / 7.3.1 Hotfix 272363 Incorrect File Ownership Local Privilege Escalation (ESA-2016-146)");
  script_summary(english:"Checks the version of EMC Avamar.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a backup solution that is affected by a
local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The EMC Avamar Data Store (ADS) or Avamar Virtual Edition (AVE)
running on the remote host is a version prior to 7.3.0 Hotfix 268253
or prior to 7.3.1 Hotfix 272363. It is, therefore, affected by a local
privilege escalation vulnerability due to incorrect file ownership.
A local attacker who has administrative access can exploit this
vulnerability to bypass some sudo command restrictions and execute
arbitrary commands as root, resulting in gaining elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2017/Jan/att-52/ESA-2016-146.txt");
  script_set_attribute(attribute:"see_also", value:"https://support.emc.com/kb/494588");
  script_set_attribute(attribute:"solution", value:
"Upgrade to EMC Avamar ADS / AVE version 7.3.0 Hotfix 268253, version
7.3.1 Hotfix 272363, or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_data_store");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:avamar_server_virtual_edition");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("emc_avamar_server_detect.nbin", "emc_avamar_server_installed_nix.nbin");
  script_require_keys("installed_sw/EMC Avamar");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("http.inc");
include("misc_func.inc");

app = "EMC Avamar";
get_install_count(app_name:app, exit_if_zero:TRUE);

install = make_array();
port = 0;

if (get_kb_item("installed_sw/EMC Avamar/local"))
{
  install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
}
else
{
  port = get_http_port(default:443);
  install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
}

version    = install['version'];
version_ui = install['display_version'];
hotfixes   = install['Hotfixes'];

note = NULL;

if (version =~ "^7\.3\.0($|[^0-9])")
{
  fix_ver = '7.3.0.233';
  fix_hf  = '268253';
}
else if (version =~ "^7\.3\.1($|[^0-9])")
{
  fix_ver = '7.3.1.125';
  fix_hf  = '272363';
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, version_ui);

if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) > 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, version_ui);

if (ver_compare(ver:version, fix:fix_ver, strict:FALSE) == 0)
{
  # Remote detection cannot detect hotfix; only flag host if paranoid reporting is enabled
  if (port != 0)
  {
    if (report_paranoia < 2) audit(AUDIT_PARANOID);      
    else
      note = "Note that Nessus was unable to remotely detect the hotfix.";
  }

  if (!empty_or_null(hotfixes))
  {
    hotfixes = split(hotfixes, sep:";", keep:FALSE);
    foreach hotfix (hotfixes)
    {
      if (fix_hf == hotfix)
        audit(AUDIT_INST_VER_NOT_VULN, app, version_ui + " HF" + hotfix);
    } 
  }
}

report =
  '\n  Installed version : ' + version_ui +
  '\n  Fixed version     : ' + fix_ver + " HF" + fix_hf +
  '\n';

if (!isnull(note))
  report += note + '\n';

security_report_v4(extra:report, port:port, severity:SECURITY_HOLE);
