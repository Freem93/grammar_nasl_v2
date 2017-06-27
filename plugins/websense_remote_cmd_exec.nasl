#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70119);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/03 14:16:36 $");

  script_cve_id("CVE-2011-5102");
  script_bugtraq_id(51086);
  script_osvdb_id(85102);
  script_xref(name:"IAVA", value:"2012-A-0141");

  script_name(english:"Websense Triton 7.1.x < 7.1.3 / 7.5.x < 7.5.3 / 7.6.0 < 7.6.1 / 7.6.2 < 7.6.3 Remote Command Execution");
  script_summary(english:"A paranoid check for local file version of ws_irpt.exe and favorites.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by a
remote command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote application is running Websense Triton, a commercial suite
of web filtering products.

The remote instance of Websense Triton fails to sanitize user-supplied
input specifically affecting the 'explorer_wse/ws_irpt.exe' file.  An
attacker can exploit this issue to execute arbitrary commands with
SYSTEM-level privileges.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Apr/228");
  # http://www.websense.com/support/article/kbarticle/v7-6-2-About-Hotfix-12-for-Websense-Web-Security-Web-Filter-Web-Security-Gateway-and-Web-Security-Gateway-Anywhere
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b760104a");
  # http://www.websense.com/support/article/kbarticle/v7-6-About-Hotfix-24-for-Websense-Web-Security-Web-Filter-Web-Security-Gateway-and-Web-Security-Gateway-Anywhere
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc3d24bb");
  # http://www.websense.com/support/article/kbarticle/v7-1-About-Hotfix-109-for-Websense-Web-Security-Web-Filter-and-Web-Security-Gateway
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5344eced");
  # http://www.websense.com/support/article/kbarticle/v7-1-1-About-Hotfix-06-for-Web-Security-Web-Filter-and-Web-Security-Gateway -> http://www.nessus.org/u?5344eced
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd549235");
  # http://www.websense.com/support/article/kbarticle/v7-5-1-About-Hotfix-12-for-Websense-Web-Security-Web-Filter-Web-Security-Gateway-and-Web-Security-Gateway-Anywhere
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65c28103");
  # http://www.websense.com/support/article/kbarticle/v7-5-About-Hotfix-78-for-Websense-Web-Security-Web-Filter-Web-Security-Gateway-and-Web-Security-Gateway-Anywhere
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?433ca77e");
  script_set_attribute(attribute:"see_also", value:"http://www.websense.com/content/Home.aspx");

  script_set_attribute(attribute:"solution", value:
"There are no known workarounds or upgrades to correct this issue.
Websense has released the following Hotfixes to address this
vulnerability :

 - Hotfix 109 for version 7.1.0
 - Hotfix 06 for version 7.1.1
 - Hotfix 78 for version 7.5.0
 - Hotfix 12 for version 7.5.1
 - Hotfix 24 for version 7.6.0
 - Hotfix 12 for version 7.6.2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:websense_web_security");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Connect to the registry
app = "Websense";
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Websense\InstallPath";

path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, app);
}

close_registry(close:FALSE);

path += "\webroot\Explorer";
exes = make_list(path+"\ws_irpt.exe");
exes = make_list(exes, path+"\favorites.exe");

# Determine versions from various files.
info = NULL;

foreach exe (exes)
{
  ver = hotfix_get_fversion(path:exe);
  if (ver["error"] != HCF_OK)
  {
    NetUseDel();
    if (ver["error"] == HCF_NOENT) audit(AUDIT_UNINST, app);
    exit(1, "Error obtaining the version of '" + exe + "'.");
  }

  ver = join(ver["value"], sep:".");

  if (ver =~ "^7\.1(\.0|$)")
    fix = "7.1.0 Hotfix 109";
  else if (ver =~ "^7\.1\.1(\.|$)")
    fix = "7.1.1 Hotfix 06";
  else if (ver =~ "^7\.5(\.$)")
    fix = "7.5.0 Hotfix 78";
  else if (ver =~ "^7\.5\.1(\.|$)")
    fix = "7.5.1 Hotfix 12";
  else if (ver =~ "^7\.6(\.0|$)")
    fix = "7.6.0 Hotfix 24";
  else if (ver =~ "^7\.6\.2(\.|$)")
    fix = "7.6.2 Hotfix 12";
  else
    continue;

  info +=
    '\n' +
    '\n  Product           : Websense' +
    '\n  File              : ' + exe +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

# Clean up
hotfix_check_fversion_end();

if (isnull(info)) audit(AUDIT_PACKAGE_NOT_AFFECTED, app);

# Report what we found.
report = NULL;
if (report_verbosity > 0)
{
   # nb: info already has a leading '\n'.
   report =
     '\nNessus found the following Websense components to be installed on' +
     '\nthe remote host :' +
     info;
}
security_hole(port:port, extra:report);
