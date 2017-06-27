#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65881);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2013-0078");
  script_bugtraq_id(58847);
  script_osvdb_id(92128);
  script_xref(name:"MSFT", value:"MS13-034");

  script_name(english:"MS13-034: Vulnerability in Microsoft Antimalware Client Could Allow Elevation of Privilege (2823482)");
  script_summary(english:"Checks version of Wdfilter.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The Microsoft Antimalware Client on the remote host is affected by a
privilege escalation vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of the Microsoft Antimalware
Client that could allow elevation of privilege due to the way that
pathnames are used.  By successfully exploiting this vulnerability, an
attacker could execute arbitrary code and take complete control of an
affected system.  But the attacker must have valid login credentials in
order to exploit the vulnerability and it cannot be exploited by
anonymous users."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-034");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 8.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_defender");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS13-034';
kb = '2781197';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# affects both windows 8
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# affects Windows 8 , but not Server 2012
if ("Windows Server 2012" >< productname) exit(0, "The host is running "+productname+" so it is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Wdfilter.sys", version:"4.2.223.0", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
