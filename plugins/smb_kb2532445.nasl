#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70395);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/06/05 18:44:28 $");

  script_cve_id("CVE-2011-4434");
  script_bugtraq_id(50687);
  script_osvdb_id(77213);

  script_name(english:"MS KB2532445: AppLocker Rules Bypass");
  script_summary(english:"Checks the version of Appid.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing an update that prevents a rules bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Microsoft KB2532445, an update that
prevents an attacker from bypassing AppLocker rules by using an Office
macro.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2532445");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7 and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_applocker_installed.nbin");
  script_require_keys("AppLocker/enabled", "SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ProductName");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/WindowsVersion");
get_kb_item_or_exit("AppLocker/enabled");

if(empty_or_null(get_kb_list("AppLocker/*/rules")))
  exit(0, "No rules exist for AppLocker to enforce.");

if (hotfix_check_sp_range(win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);
productname = get_kb_item_or_exit('SMB/ProductName');
if ('Enterprise' >!< productname && 'Ultimate' >!< productname) exit(0, 'The host is not affected because the Windows edition is not Enterprise or Ultimate.');

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, 'Failed to get the system root.');

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Appidsvc.dll", version:"6.1.7601.21798", min_version:"6.1.7600.16000", dir:"\system32") ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Appidsvc.dll", version:"6.1.7600.21035", min_version:"6.1.7600.16000", dir:"\system32")
)
{
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
