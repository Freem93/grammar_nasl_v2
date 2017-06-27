#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44419);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0239", "CVE-2010-0240", "CVE-2010-0241", "CVE-2010-0242");
  script_bugtraq_id(38061, 38062, 38063, 38064);
  script_osvdb_id(62247, 62248, 62249, 62250);
  script_xref(name:"IAVA", value:"2010-A-0030");
  script_xref(name:"MSFT", value:"MS10-009");

  script_name(english:"MS10-009: Vulnerabilities in Windows TCP/IP Could Allow Remote Code Execution (974145)");
  script_summary(english:"Checks version of tcpip.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has multiple vulnerabilities in its TCP/IP
implementation."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has the following vulnerabilities in its
TCP/IP implementation :

  - Hosts with IPv6 enabled perform insufficient bounds
    checking when processing specially crafted ICMPv6 Router
    Advertisement packets.  A remote attacker could exploit
    this to execute arbitrary code. (CVE-2010-0239)

  - Specially crafted Encapsulating Security Payloads (ESP)
    are not processed properly.  A remote attacker could
    exploit this to execute arbitrary code. (CVE-2010-0240)

  - Hosts with IPv6 enabled perform insufficient bounds
    checking when processing specially crafted ICMPv6 Route
    Information packets.  A remote attacker could exploit
    this to execute arbitrary code. (CVE-2010-0241)

  - Specially crafted TCP packets with a malformed
    selective acknowledgment (SACK) value can cause the
    system to stop responding and automatically restart.  A
    remote attacker could exploit this to cause a denial of
    service. (CVE-2009-0242)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-009");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS10-009';
kbs = make_list("974145");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "974145";

if (
  # Vista SP0 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"Tcpip.sys", version:"6.0.6000.16973",   min_version:"6.0.6000.0",     dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"Tcpip.sys", version:"6.0.6000.21175",   min_version:"6.0.6000.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Vista / 2k8 SP1 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"Tcpip.sys", version:"6.0.6001.18377",   min_version:"6.0.6001.0",     dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"Tcpip.sys", version:"6.0.6001.22577",   min_version:"6.0.6001.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Vista / 2k8 SP2 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"Tcpip.sys", version:"6.0.6002.18160",   min_version:"6.0.6002.0",     dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"Tcpip.sys", version:"6.0.6002.22283",   min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
