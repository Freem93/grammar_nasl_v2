#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70683);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/10/29 18:26:50 $");

  script_bugtraq_id(63195);
  script_osvdb_id(98635);

  script_name(english:"Panda AdminSecure Communications Agent < 4.50.0.10 Directory Traversal");
  script_summary(english:"Checks version of pagent.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Panda AdminSecure Communications Agent software, which is used for
centralized management of Panda Antivirus, installed on the remote
Windows host contains a flaw in the handling of MESSAGE_FROM_REMOTE
messages.  The software does not properly sanitize inputs, allowing an
attacker to craft a special message that allows traversing outside of a
restricted path.  This may allow a remote attacker to overwrite
arbitrary files and execute remote code with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-250/");
  script_set_attribute(attribute:"see_also", value:"http://www.pandasecurity.com/enterprise/support/card?id=40081");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Panda AdminSecure hotfix 4_50_00_0032 or later and update
all connected agents.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pandasecurity:panda_antivirus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

path = null;
appname = "Panda AdminSecure Communications Agent";
fix = "4.50.0.10";
report = "";
port = kb_smb_transport();

registry_init();

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "SOFTWARE\Panda Software";

subkeys = get_registry_subkeys(handle:hklm, key:key);

foreach subkey (subkeys)
{
  if (strlen(subkey) && subkey =~ "^Panda Administrator [0-9.]+$")
  {
    item = key + "\" + subkey + "\PLAgent\InstallPath";
    value = get_registry_value(handle:hklm, item:item);
    if (!isnull(value))
    {
      path = value;
      break;
    }
  }
}

RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

exe = path + "\Pav_Agent\Pagent.exe";

version = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();
if (version['error'] == HCF_OK) ver = join(version['value'], sep:'.');

if (isnull(ver)) audit(AUDIT_VER_FAIL, appname);

# Check the version number.
if (ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + exe +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix +
      '\n';
  }
}

if (report != "")
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver, path+"\Pav_Agent");

