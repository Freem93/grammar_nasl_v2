#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79137);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-4077");
  script_bugtraq_id(70944);
  script_osvdb_id(114525);
  script_xref(name:"MSFT", value:"MS14-078");
  script_xref(name:"IAVA", value:"2014-A-0179");

  script_name(english:"MS14-078: Vulnerability in IME (Japanese) Could Allow Elevation of Privilege (2992719)");
  script_summary(english:"Checks versions of several .dll files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a privilege escalation
vulnerability in the Microsoft Input Method Editor (IME) (Japanese)
component that is triggered when loading dictionary files. An attacker
can exploit this vulnerability by convincing a user to open a
specially crafted file, resulting in a sandbox escape and an
escalation of privileges in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-078");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, and Office 2007 SP3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS14-078';

kbs = make_list(
  "2889913",
  "2991963"
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

vuln = 0;

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

############################
#
# Checks for KB 2991963
#
############################
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"imjp10k.dll", version:"10.1.7601.22764", min_version:"10.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:'2991963') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"imjp10k.dll", version:"10.1.7601.18556", min_version:"10.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:'2991963') ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"imjp10k.dll", version:"10.0.6002.23459", min_version:"10.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:'2991963') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"imjp10k.dll", version:"10.0.6002.19154", min_version:"10.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:'2991963') ||

  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"IMJP8K.DLL", version:"8.1.7104.0", dir:"\system32", bulletin:bulletin, kb:'2991963')
) vuln++;

############################
#
# Checks for KB 2889913
#
############################
arch = get_kb_item_or_exit("SMB/ARCH");

office_ver = hotfix_check_office_version();

path = hotfix_get_commonfilesdirx86();
if (!path)
{
  if (arch == 'x64') audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
  else path = hotfix_get_commonfilesdir();
}
if (!path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

# Office 2007 SP3
if (office_ver['12.0'])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && office_sp == 3 && get_kb_item("SMB/Registry/Uninstall/Enumerated"))
  {
    display_names = get_kb_list_or_exit('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
    if (display_names)
    {
      foreach item (keys(display_names))
      {
        if ('Microsoft Office IME (Japanese) 2007' >< display_names[item])
        {
          if (hotfix_is_vulnerable(file:"imjpdapi.dll", version:"12.0.6704.5000", min_version:'12.0.0.0', path:path + "\Microsoft Shared\IME12\IMEJP", bulletin:bulletin, kb:"2889913")) vuln++;
          break;
        }
      }
    }
  }
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
