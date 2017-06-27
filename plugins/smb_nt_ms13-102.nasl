#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71317);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/23 21:44:07 $");

  script_cve_id("CVE-2013-3878");
  script_bugtraq_id(64088);
  script_osvdb_id(100768);
  script_xref(name:"MSFT", value:"MS13-102");
  script_xref(name:"IAVA", value:"2013-A-0226");

  script_name(english:"MS13-102: Vulnerability in LRPC Client Could Allow Elevation of Privilege (2898715)");
  script_summary(english:"Checks version of Rpcrt4.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A client on the host is vulnerable to a privilege escalation
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A privilege escalation vulnerability exists in the LRPC client on the
host.  Exploitation occurs when an authenticated attacker spoofs an LRPC
server and uses a specially crafted LPC port message to cause a stack-
based buffer overflow condition on the LRPC client."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-102");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2003 and XP.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS13-102';
kb = '2898715';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (

  # Windows 2003 and XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Rpcrt4.dll", version:"5.2.3790.5254", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Rpcrt4.dll", version:"5.1.2600.6477", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
