#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51913);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2011-0043", "CVE-2011-0091");
  script_bugtraq_id(46130, 46140);
  script_osvdb_id(70834, 70835);
  script_xref(name:"MSFT", value:"MS11-013");

  script_name(english:"MS11-013: Vulnerabilities in Kerberos Could Allow Elevation of Privilege (2496930)");
  script_summary(english:"Checks version of Kerberos.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote implementation of Kerberos is affected by one or more
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The implementation of Kerberos on the remote Windows host is affected
by one or more vulnerabilities :

  - Microsoft's Kerberos implementation uses a weak hashing
    mechanism, which can allow for certain aspects of a
    Kerberos service ticket to be forged. Note that this is
    not exploitable on domains where the domain controllers
    are running Windows Server 2008 or Windows Server 2008
    R2. (CVE-2011-0043)

  - An attacker can force a downgrade in Kerberos
    communication between a client and server to a weaker
    encryption standard than negotiated originally by means
    of a man-in-the-middle attack because Windows does not
    correctly enforce the stronger default encryption
    standards included in Windows 7 and Windows Server 2008
    R2. Note that this issue only affects implementations
    of Kerberos on Windows 7 and Windows Server 2008 R2.
    (CVE-2011-0091)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-013");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, 7, and
2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS11-013';

kbs = make_list("2425227", "2478971");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / Server 2008 R2
  # - KB 2425227
  hotfix_is_vulnerable(os:"6.1",                   file:"Kerberos.dll", version:"6.1.7601.21624", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"2425227") ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Kerberos.dll", version:"6.1.7601.17527", min_version:"6.1.7601.0",     dir:"\system32", bulletin:bulletin, kb:"2425227") ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Kerberos.dll", version:"6.1.7600.20861", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2425227") ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Kerberos.dll", version:"6.1.7600.16722", min_version:"6.1.7600.0",     dir:"\system32", bulletin:bulletin, kb:"2425227") ||

  # Windows 2003 and XP x64
  # - KB 2478971
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Kerberos.dll", version:"5.2.3790.4806",                                dir:"\system32", bulletin:bulletin, kb:"2478971") ||

  # Windows XP x86
  # - KB 2478971
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Kerberos.dll", version:"5.1.2600.6059",                                dir:"\system32", bulletin:bulletin, kb:"2478971")
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
