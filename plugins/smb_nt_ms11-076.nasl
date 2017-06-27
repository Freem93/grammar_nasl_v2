#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56450);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2011-2009");
  script_bugtraq_id(49943);
  script_osvdb_id(76205);
  script_xref(name:"MSFT", value:"MS11-076");
  script_xref(name:"IAVB", value:"2011-B-0124");

  script_name(english:"MS11-076: Vulnerability in Windows Media Center Could Allow Remote Code Execution (2604926)");
  script_summary(english:"Checks the version of psisdecd.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Windows
Media Center."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Windows Media Center that
fails to properly restrict the path used for loading external libraries.

If an attacker can trick a user into opening a file that resides in the
same directory as a specially crafted DLL file, he can leverage this
issue to execute arbitrary code in that DLL file subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-076");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Vista, 7, and
Media Center TV Pack."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS11-076';
kbs = make_list("2579686", "2579692");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("Windows Vista" >!< productname && "Windows 7" >!< productname)
  exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "2579686";
if (
  # Windows Media Center TV Pack 2008 for Windows Vista
  #hotfix_is_vulnerable(os:"6.0", file:"psisdecd.dll", version:"???",  min_version:"6.6.1000.0", dir:"\system32", bulletin:bulletin, kb:"2579692") ||

  # Windows 7
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"psisdecd.dll", version:"6.6.7601.21792", min_version:"6.6.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"psisdecd.dll", version:"6.6.7601.17669", min_version:"6.1.7600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"psisdecd.dll", version:"6.6.7600.21030", min_version:"6.6.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"psisdecd.dll", version:"6.6.7600.16867", min_version:"6.6.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista
  hotfix_is_vulnerable(os:"6.0",       file:"psisdecd.dll", version:"6.6.6002.22686", min_version:"6.6.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       file:"psisdecd.dll", version:"6.6.6002.18496", min_version:"6.6.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       file:"psisdecd.dll", version:"6.6.6001.22948", min_version:"6.6.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",       file:"psisdecd.dll", version:"6.6.6001.18672", min_version:"6.6.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb)
)
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
