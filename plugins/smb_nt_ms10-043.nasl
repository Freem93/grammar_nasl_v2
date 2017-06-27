#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47711);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/23 21:35:39 $");

  script_cve_id("CVE-2009-3678");
  script_bugtraq_id(40237);
  script_osvdb_id(64731);
  script_xref(name:"MSFT", value:"MS10-043");

  script_name(english:"MS10-043: Vulnerability in Canonical Display Driver Could Allow Remote Code Execution (2032276)");
  script_summary(english:"Checks version of cdd.dll");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote Windows host
through the Canonical Display Driver.");
  script_set_attribute(attribute:"description", value:
"A flaw exists in the way the Microsoft Canonical Display Driver
(cdd.dll) parses information copied from user mode to kernel mode.

If the Windows Aero theme is enabled, an attacker who tricks a user on
the affected host into viewing a specially crafted image using an
application that uses the APIs for GDI for rendering images can
leverage this issue to cause the affected system to stop responding
and restart or even to execute arbitrary code, although this is
unlikely due to memory randomization.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-043");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 7 and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-043';
kbs = make_list("2032276");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);
if (arch != "x64") exit(0, "Only x64-based systems are affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", file:"cdd.dll", version:"6.1.7600.20715", min_version:"6.1.7600.20000", dir:"System32", bulletin:bulletin, kb:'2032276') ||
  hotfix_is_vulnerable(os:"6.1", file:"cdd.dll", version:"6.1.7600.16595", min_version:"6.1.7600.16000", dir:"System32", bulletin:bulletin, kb:'2032276')
)
{
  set_kb_item(name:"SMB/Missing/MS10-043", value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
