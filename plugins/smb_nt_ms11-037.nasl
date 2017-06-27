#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55117);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/04/23 21:35:40 $");

  script_cve_id("CVE-2011-1894");
  script_bugtraq_id(48205);
  script_osvdb_id(72935);
  script_xref(name:"MSFT", value:"MS11-037");
  script_xref(name:"IAVB", value:"2011-B-0065");

  script_name(english:"MS11-037: Vulnerability in MHTML Could Allow Information Disclosure (2544893)");
  script_summary(english:"Checks version of Inetcomm.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is affected by an information disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A flaw exists in the way MHTML interprets MIME-formatted requests for
content blocks within a document.  By exploiting the flaw, an attacker
could cause a victim to run malicious scripts when visiting various
websites that could result in information disclosure."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-037");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = 'MS11-037';
kb = "2544893";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Inetcomm.dll", version:"6.1.7601.21719", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Inetcomm.dll", version:"6.1.7601.17609", min_version:"6.1.7600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Inetcomm.dll", version:"6.1.7600.20958", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Inetcomm.dll", version:"6.1.7600.16807", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Inetcomm.dll", version:"6.0.6002.22634", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Inetcomm.dll", version:"6.0.6002.18463", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Inetcomm.dll", version:"6.0.6001.22911", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Inetcomm.dll", version:"6.0.6001.18645", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP 64-bit
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Inetcomm.dll", version:"6.0.3790.4913", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP 32-bit
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Inetcomm.dll", version:"6.0.2900.6157", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
