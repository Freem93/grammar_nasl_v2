#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18215);
 script_version("$Revision: 1.32 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_bugtraq_id(13248);
 script_cve_id("CVE-2005-1191");
 script_osvdb_id(15707);
 script_xref(name:"MSFT", value:"MS05-024");
 script_xref(name:"EDB-ID", value:"25454");

 script_name(english:"MS05-024: Vulnerability in Web View Could Allow Code Execution (894320)");
 script_summary(english:"Determines the presence of KB894320");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Explorer.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Windows that contains
a security flaw in the Web View of the Windows Explorer that could allow
an attacker to execute arbitrary code on the remote host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have him preview it using the Web View with the
Windows Explorer.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms05-024");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Windows 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/19");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/05/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS05-024';
kb = '894320';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'3,4') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (hotfix_is_vulnerable(os:"5.0", file:"Webvw.dll", version:"5.0.3900.7036", dir:"\system32", bulletin:bulletin, kb:kb))
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
