#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56824);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/03/02 21:25:10 $");

  script_name(english:"MS KB2506014: Update for the Windows Operating System Loader");
  script_summary(english:"Checks version of winload.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Windows host does not properly enforce driver signing."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of the Windows OS Loader
(winload.exe) which does not properly enforce driver signing.  This
could result in unsigned drivers being loaded by winload.exe. 

While this update does not address any specific vulnerabilities, it
prevents winload.exe from loading unsigned binaries.  This technique
is commonly used by malware (e.g. rootkits) to stay resident on a
system after the initial infection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/security/advisory/2506014"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for the 64-bit editions of
Windows Vista, 2008, 7, and 2008 R2 :

http://support.microsoft.com/kb/2506014"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/ARCH");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");


get_kb_item_or_exit('SMB/WindowsVersion');
arch = get_kb_item_or_exit('SMB/ARCH');
if (arch != 'x64')
  exit(0, '32-bit versions of Windows are not affected.');
if (hotfix_check_sp(vista:3, win7:2) <= 0)
  exit(0, 'The host is not affected based on its version / service pack.');
if (!is_accessible_share())
  exit(1, 'is_accessible_share() failed.');

kb = '2506014';

if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"winload.exe", version:"6.1.7601.21655", min_version:"6.1.7601.21000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"winload.exe", version:"6.1.7601.17556", min_version:"6.1.7601.17000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, arch:"x64", file:"winload.exe", version:"6.1.7600.20897", min_version:"6.1.7600.20000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, arch:"x64", file:"winload.exe", version:"6.1.7600.16757", min_version:"6.1.7600.16000", dir:"\system32", kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"winload.exe", version:"6.0.6002.22596", min_version:"6.0.6002.22000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, arch:"x64", file:"winload.exe", version:"6.0.6002.18411", min_version:"6.0.6002.18000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"winload.exe", version:"6.0.6001.22861", min_version:"6.0.6001.22000", dir:"\system32", kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, arch:"x64", file:"winload.exe", version:"6.0.6001.18606", min_version:"6.0.6001.18000", dir:"\system32", kb:kb)
)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}


