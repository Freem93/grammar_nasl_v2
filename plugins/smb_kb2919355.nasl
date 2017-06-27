# @DEPRECATED@
#
# This script has been deprecated as Microsoft suspended release of 
# Windows 8.1 Update KB 2919355 to WSUS servers.
#
# http://blogs.technet.com/b/wsus/archive/2014/04/08/windows-8-1-update-prevents-interaction-with-wsus-3-2-over-ssl.aspx
#
# Disabled on 2014/04/09.
#

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73381);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/04/10 00:55:19 $");

  script_name(english:"MS KB2919355 : Windows RT 8.1, Windows 8.1, and Windows Server 2012 R2 Update April, 2014");
  script_summary(english:"Checks version of kernel32.dll");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing an update that contains unspecified
security fixes.");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/2919355");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 8.1, RT 8.1, and
Server 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

# Deprecated.
exit(0, "Microsoft has suspended release of the Windows 8.1 Update KB 2919355 to WSUS servers (http://blogs.technet.com/b/wsus/archive/2014/04/08/windows-8-1-update-prevents-interaction-with-wsus-3-2-over-ssl.aspx).");


include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

kb = '2919355';

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

# fix does not increment sp version
if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"kernel32.dll", version:"6.3.9600.17031", min_version:"6.3.9600.16000", dir:"\system32", kb:kb)
)
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
