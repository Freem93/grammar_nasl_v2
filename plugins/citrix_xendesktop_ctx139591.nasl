#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76571);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/17 13:42:20 $");

  script_cve_id("CVE-2014-4700");
  script_bugtraq_id(68530);
  script_osvdb_id(109010);

  script_name(english:"Citrix XenDesktop 4.x / 5.x / 7.x Unauthorized Access (CTX139591)");
  script_summary(english:"Checks the version of picaSvc2.exe.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by an unauthorized access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Citrix XenDesktop that is
affected by an unauthorized access vulnerability. A flaw exists that
could result in a user gaining unauthorized access to another user's
desktop.

Note that this vulnerability only affects configurations when pooled
random desktop groups are enabled and the 'ShutdownDesktopsAfterUse'
setting is set to the non-default state of disabled.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX139591");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate hotfix or set 'ShutdownDesktopsAfterUse' to
enabled.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xendesktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("citrix_xendesktop_virtual_agent_ctx135813.nasl");
  script_require_keys("SMB/Citrix_XenDesktop/Installed", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Citrix_XenDesktop/Installed");

if (report_paranoia < 2)  audit(AUDIT_PARANOID);

appname = 'Citrix XenDesktop Virtual Desktop Agent';

port = kb_smb_transport();

version = NULL;
path = NULL;

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Citrix\Install";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Location");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (isnull(path)) audit(AUDIT_PATH_NOT_DETERMINED, appname);

share = hotfix_path2share(path:path);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

# Check for 5.x branch
if (
  hotfix_is_vulnerable(
    dir:"\ICAService",
    file:'picaSvc.exe',
    path:path,
    version:'6.3.400.16')
) vuln++;

# Check for 7.x branch
if (
  hotfix_is_vulnerable(
    dir:"\ICAService",
    file:'picaSvc2.exe',
    path:path,
    version:'7.1.1.4100')
) vuln++;

if (vuln)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_INST_VER_NOT_VULN, appname);
}
