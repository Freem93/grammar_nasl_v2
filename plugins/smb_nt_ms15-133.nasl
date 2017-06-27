#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87262);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/29 19:33:20 $");

  script_cve_id("CVE-2015-6126");
  script_bugtraq_id(78509);
  script_osvdb_id(131344);
  script_xref(name:"MSFT", value:"MS15-133");
  script_xref(name:"IAVA", value:"2015-A-0304");

  script_name(english:"MS15-133: Security Update for Windows PGM to Address Elevation of Privilege (3116130)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by an elevation of privilege vulnerability in the
Pragmatic General Multicast (PGM) protocol, installed with the MSMQ
service, due to a race condition that can result in references being
made to already freed memory. An local attacker can exploit this, via
a specially crafted application, to gain elevated privileges on the
affected host.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-133");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Vista, 2008, 7, 2008 R2,
8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl" , "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS15-133';

kbs = make_list(
  '3109103', # Vista, 2008, 7, 2008 R2, 8, RT, 2012, 8.1, RT 8.1, and 2012 R2
  '3116869', # Windows 10
  '3116900'  # Windows 10 Version 1511
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0',  win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"Rmcast.sys", version:"10.0.10586.20", min_version:"10.0.10586.0", dir:"\system32\drivers", bulletin:bulletin, kb:"3116900") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"Rmcast.sys", version:"10.0.10240.16603", dir:"\system32\drivers", bulletin:bulletin, kb:"3116869") ||

  # Windows 8.1 / Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Rmcast.sys", version:"6.3.9600.18119", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3109103") ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Rmcast.sys", version:"6.2.9200.21683", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:"3109103") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Rmcast.sys", version:"6.2.9200.17565", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3109103") ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Rmcast.sys", version:"6.1.7601.23260", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:"3109103") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Rmcast.sys", version:"6.1.7601.19055", min_version:"6.1.7600.17000", dir:"\system32\drivers", bulletin:bulletin, kb:"3109103") ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Rmcast.sys", version:"6.0.6002.23844", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:"3109103") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Rmcast.sys", version:"6.0.6002.19534", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:"3109103")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
