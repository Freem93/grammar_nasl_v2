#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79128);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-4118");
  script_bugtraq_id(70957);
  script_osvdb_id(114531);
  script_xref(name:"MSFT", value:"MS14-067");

  script_name(english:"MS14-067: Vulnerability in XML Core Services Could Allow Remote Code Execution (2993958)");
  script_summary(english:"Checks the file version of Msxml3.dll.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft XML Core Services
(MSXML) that is affected by a remote code execution vulnerability. An
attacker can exploit this issue by convincing a user to visit a
specially crafted website, allowing the attacker to execute code with
the current user's permissions.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/ms14-067.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1 and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS14-067';
kb = "2993958";
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Msxml3.dll", version:"8.110.9600.17324", min_version:"8.110.9600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # 8.0 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Msxml3.dll", version:"8.110.9200.21211", min_version:"8.110.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Msxml3.dll", version:"8.110.9200.17092", min_version:"8.110.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msxml3.dll", version:"8.110.7601.22782", min_version:"8.110.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msxml3.dll", version:"8.110.7601.18576", min_version:"8.110.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msxml3.dll", version:"8.100.5009.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Msxml3.dll", version:"8.100.1056.0", dir:"\system32", bulletin:bulletin, kb:kb)
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
