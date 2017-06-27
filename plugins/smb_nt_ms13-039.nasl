#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66414);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/03 13:34:41 $");

  script_cve_id("CVE-2013-1305");
  script_bugtraq_id(59784);
  script_osvdb_id(93300);
  script_xref(name:"MSFT", value:"MS13-039");
  script_xref(name:"IAVB", value:"2013-B-0053");

  script_name(english:"MS13-039: Vulnerability in HTTP.sys Could Allow Denial of Service (2829254)");
  script_summary(english:"Checks file version of HTTP.sys");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is potentially affected by a vulnerability that
could allow for a denial of service condition."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Windows installed on the remote host is potentially
affected by a denial of service vulnerability because the HTTP protocol
stack (HTTP.sys) may improperly handle a malicious HTTP header, causing
an infinite loop in the HTTP protocol.  A remote, unauthenticated
attacker could exploit this flaw by sending a specially crafted HTTP
packet to the affected system, which could trigger the vulnerability."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-086/");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-039");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 8 and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS13-039';
kb = '2829254';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Http.sys", version:"6.2.9200.20660", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Http.sys", version:"6.2.9200.16556", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
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
