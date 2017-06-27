#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74422);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/11/18 02:26:38 $");

  script_cve_id("CVE-2014-0296");
  script_bugtraq_id(67865);
  script_osvdb_id(107828);
  script_xref(name:"MSFT", value:"MS14-030");

  script_name(english:"MS14-030: Vulnerability in Remote Desktop Could Allow Tampering (2969259)");
  script_summary(english:"Checks version of rdpcorets.dll.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is affected by a tampering vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a tampering vulnerability due
to an encryption weakness in the Remote Desktop Protocol (RDP). An
attacker could exploit this vulnerability to modify the traffic
content of an active RDP session.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-030");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 8, 2012, 8.1,
and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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

bulletin = 'MS14-030';
kb = '2965788';

kbs = make_list(
  2966034,  # Windows 8.1/2012 R2 w/o 2919355
  2965788   # Everything else.
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Server 2008 is not affected.
product_name = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Server 2008" >< product_name) audit(AUDIT_INST_VER_NOT_VULN, product_name);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"rdpcorets.dll", version:"6.3.9600.17116", min_version:"6.3.9600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # Windows 8.1/2012 R2 w/o 2919355
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"rdpcorets.dll", version:"6.3.9600.16663", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"2966034") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"rdpcorets.dll", version:"6.2.9200.16912", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"rdpcorets.dll", version:"6.2.9200.21035", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 SP1
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpcorets.dll", version:"6.2.9200.16912", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpcorets.dll", version:"6.2.9200.21035", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpcorets.dll", version:"6.1.7601.18465", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpcorets.dll", version:"6.1.7601.22678", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb)
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
