#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80494);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id("CVE-2015-0006");
  script_bugtraq_id(71930);
  script_osvdb_id(116956);
  script_xref(name:"MSFT", value:"MS15-005");
  script_xref(name:"IAVB", value:"2015-B-0004");

  script_name(english:"MS15-005: Vulnerability in Network Location Awareness Service Could Allow Security Feature Bypass (3022777)");
  script_summary(english:"Checks for nlasvc.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Network Location Awareness (NLA) service on the remote host is
affected by a security bypass vulnerability due to a failure to
validate whether it is connected to a trusted domain or an untrusted
network. This could cause the system to unintentionally configure
applications insecurely (e.g. the firewall policy) when connecting to
an untrusted network. An attacker on the same network can exploit this
by spoofing responses to DNS or LDAP requests made by the targeted
system.

Note that Microsoft has no plans to release an update for Windows 2003
even though it is affected by this vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-005");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS15-005';
kb = "3022777";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

vuln = FALSE;
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if ("2003" >< productname)
{
  info = '
The remote host is running Windows 2003, which is vulnerable to MS15-005.
Microsoft has no plans to release a fix for MS15-005 on Windows 2003.
No workarounds are available.\n';
  hotfix_add_report(info, bulletin:bulletin);
  vuln = TRUE;
}
else if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Nlasvc.dll", version:"6.3.9600.17550", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Nlasvc.dll", version:"6.2.9200.21316", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Nlasvc.dll", version:"6.2.9200.17199", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Nlasvc.dll", version:"6.1.7601.22893", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Nlasvc.dll", version:"6.1.7601.18685", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Nlasvc.dll", version:"6.0.6002.23557", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Nlasvc.dll", version:"6.0.6002.19250", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  vuln = TRUE;
}

if (vuln)
{
  if ('2003' >!< productname)
  {
    set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  }

  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
