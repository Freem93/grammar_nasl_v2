#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73520);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/04/15 18:32:29 $");

  script_cve_id("CVE-2014-0347");
  script_bugtraq_id(66687);
  script_osvdb_id(105478);
  script_xref(name:"CERT", value:"568252");

  script_name(english:"Websense Triton 7.7.3 < 7.7.3 Hotfix 31 Information Disclosure");
  script_summary(english:"A paranoid check for file version of ws_irpt.exe and favorites.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote application is running Websense Triton Unified Security
Center, a component of the commercial suite of web filtering products.

The remote instance of Websense Triton Unified Security Center fails
to sanitize user-supplied input data in the 'Log Database' and 'User
Directories' areas of the 'Settings' component. This error could allow
an authenticated attacker to obtain credential information belonging
to other users and possibly those owning higher privileges.");
  # https://www.websense.com/content/mywebsense-hotfixes.aspx?patchid=894&prodidx=20&osidx=0&intidx=0&versionidx=0
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cccef1f");

  script_set_attribute(attribute:"solution", value:
"There are no known workarounds or upgrades to correct this issue.
Websense has released the following Hotfixes to address this
vulnerability :

  - Web Security Gateway Anywhere v7.7.3 Hotfix 31
  - Web Security Gateway v7.7.3 Hotfix 31
  - Websense Web Security v7.7.3 Hotfix 31
  - Websense Web Filter v7.7.3 Hotfix 31");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:triton_web_security");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:websense:triton_web_filter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
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
    audit(AUDIT_VER_FAIL, exe);
  }

  ver = join(ver["value"], sep:".");

  if (ver =~ "^7\.7\.3(\.|$)")
    fix = "7.7.3 Hotfix 31";
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
security_note(port:port, extra:report);
