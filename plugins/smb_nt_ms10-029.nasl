#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45516);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2015/04/23 21:11:58 $");

  script_cve_id("CVE-2010-0812");
  script_bugtraq_id(39352);
  script_osvdb_id(63747);
  script_xref(name:"MSFT", value:"MS10-029");
  script_xref(name:"IAVB", value:"2010-B-0030");

  script_name(english:"MS10-029: Vulnerability in Windows ISATAP Component Could Allow Spoofing (978338)");
  script_summary(english:"Checks version of tcpip.sys / tcpip6.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is vulnerable to network spoofing attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A spoofing vulnerability exists in the Microsoft Windows IPv6 stack
due to the way Windows checks the inner packet's IPv6 source address
in a tunneled ISATAP packet.

A remote attacker could exploit this by spoofing a trusted IP address,
which could be used to bypass security restrictions based on source
IP.  This could also be exploited to disclose information if a
targeted host replies to the message using the spoofed IPv6 address."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-029");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
and 2008."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-029';
kbs = make_list("978338");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "978338";

if (
  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Tcpip.sys", version:"6.0.6002.22341", min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Tcpip.sys", version:"6.0.6002.18209", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Tcpip.sys", version:"6.0.6001.22636", min_version:"6.0.6001.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Tcpip.sys", version:"6.0.6001.18427", min_version:"6.0.6001.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Tcpip.sys", version:"6.0.6000.21226", min_version:"6.0.6000.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Tcpip.sys", version:"6.0.6000.17021", min_version:"6.0.6000.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Tcpip6.sys", version:"5.2.3790.4662",                               dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Tcpip6.sys", version:"5.1.2600.5935", min_version:"5.1.2600.5000",  dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Tcpip6.sys", version:"5.1.2600.3667",                               dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
