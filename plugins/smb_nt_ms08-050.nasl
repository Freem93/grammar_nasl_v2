#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33879);
 script_version("$Revision: 1.26 $");
 script_cvs_date("$Date: 2016/05/06 17:11:38 $");

 script_cve_id("CVE-2008-0082");
 script_bugtraq_id(30551);
 script_osvdb_id(47403);
 script_xref(name:"MSFT", value:"MS08-050");

 script_name(english:"MS08-050: Vulnerability in Windows Messenger Could Allow Information Disclosure (955702)");
 script_summary(english:"Checks the version of Windows Messenger");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to an information disclosure due to
Windows Messenger");
 script_set_attribute(attribute:"description", value:
"The remote host is running Windows Messenger.

There is a vulnerability in the remote version of this software that may
lead to an information disclosure which could allow an attacker to
change the state of a user, to get contact information or to initiate
audio and video chat sessions.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-050");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(200);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-50';
kb = '899283';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

# nb: Windows 2000 with Windows Messenger 4.7 is affected, but
#     Microsoft says 4.7 is not supported on Windows 2000.
if (hotfix_check_sp_range(xp:'2,3', win2003:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_programfilesdir();
if (!rootfile) exit(1, "Failed to get the Program Files directory.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.1", file:"Msgsc.dll", version:"4.7.0.3002", path:rootfile, dir:"\Messenger", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Msgsc.dll", version:"4.7.0.3002", path:rootfile, dir:"\Messenger", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
