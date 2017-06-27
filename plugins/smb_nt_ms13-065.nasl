#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69330);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3183");
  script_bugtraq_id(61666);
  script_osvdb_id(96197);
  script_xref(name:"MSFT", value:"MS13-065");

  script_name(english:"MS13-065: Vulnerability in ICMPv6 Could Allow Denial of Service (2868623)");
  script_summary(english:"Checks version of tcpip.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is affected by a denial of service
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is affected by a denial of service
vulnerability due to the Windows TCP/IP stack improperly allocating
memory for incoming ICMPv6 packets.  An attacker could use a specially
crafted ICMPv6 packet to exploit this vulnerability and cause a target
system to stop responding until it is restarted."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-065");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, and 2012."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-065';
kb = "2868623";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"tcpip.sys", version:"6.2.9200.20767", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"tcpip.sys", version:"6.2.9200.16659", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"tcpip.sys", version:"6.1.7601.22378", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"tcpip.sys", version:"6.1.7601.18203", min_version:"6.1.7600.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"tcpip.sys", version:"6.0.6002.23152", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"tcpip.sys", version:"6.0.6002.18880", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
