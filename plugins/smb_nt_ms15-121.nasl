#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86827);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/29 19:33:19 $");

  script_cve_id("CVE-2015-6112");
  script_bugtraq_id(77484);
  script_osvdb_id(130064);
  script_xref(name:"MSFT", value:"MS15-121");
  script_xref(name:"IAVA", value:"2015-A-0273");

  script_name(english:"MS15-121: Security Update for Schannel to Address Spoofing (3081320)");
  script_summary(english:"Checks the version of schannel.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a spoofing vulnerability due to
a weakness in the Secure Channel (SChannel) TLS protocol
implementation. A man-in-the-middle attacker can exploit this
vulnerability to impersonate a victim on any other server that uses
the same credentials as those used between the client and server where
the attack is initiated.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-121");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS15-121';
kbs = make_list('3081320');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"schannel.dll", version:"6.3.9600.18088", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3081320") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"schannel.dll", version:"6.2.9200.21676", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3081320") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"schannel.dll", version:"6.2.9200.17559", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3081320") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"schannel.dll", version:"6.1.7601.23249", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3081320") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"schannel.dll", version:"6.1.7601.19044", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3081320") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"schannel.dll", version:"6.0.6002.23814", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3081320") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"schannel.dll", version:"6.0.6002.19503", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3081320")
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
