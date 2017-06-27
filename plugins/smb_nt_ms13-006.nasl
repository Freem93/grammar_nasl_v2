#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63424);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-0013");
  script_bugtraq_id(57144);
  script_osvdb_id(88967);
  script_xref(name:"MSFT", value:"MS13-006");
  script_xref(name:"IAVB", value:"2013-B-0003");

  script_name(english:"MS13-006: Vulnerability in Microsoft Windows Could Allow Security Feature Bypass (2785220)");
  script_summary(english:"Checks version of Ncrypt.dll and Ncryptsslp.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is affected by a security feature bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a flaw in the handling of SSL version
3 (SSLv3) and TLS (Transport Layer Security) protocols.  An attacker can
inject specially crafted content into an SSL/TLS session, which could
allow an attacker to bypass security features of SSLv3 and TLS protocols
in order to intercept communications."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-006");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, and 2012."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS13-006';
kb = '2785220';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Ncryptsslp.dll", version:"6.2.9200.16464", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Ncryptsslp.dll", version:"6.2.9200.20568", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Ncrypt.dll", version:"6.1.7600.17172", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Ncrypt.dll", version:"6.1.7600.21377", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ncrypt.dll", version:"6.1.7601.18007", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ncrypt.dll", version:"6.1.7601.22169", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Vista Service Pack 2 / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ncrypt.dll", version:"6.0.6002.18736", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ncrypt.dll", version:"6.0.6002.22981", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb)

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
