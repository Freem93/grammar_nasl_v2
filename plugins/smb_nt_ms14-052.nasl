#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77572);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id(
    "CVE-2013-7331",
    "CVE-2014-2799",
    "CVE-2014-4059",
    "CVE-2014-4065",
    "CVE-2014-4079",
    "CVE-2014-4080",
    "CVE-2014-4081",
    "CVE-2014-4082",
    "CVE-2014-4083",
    "CVE-2014-4084",
    "CVE-2014-4085",
    "CVE-2014-4086",
    "CVE-2014-4087",
    "CVE-2014-4088",
    "CVE-2014-4089",
    "CVE-2014-4090",
    "CVE-2014-4091",
    "CVE-2014-4092",
    "CVE-2014-4093",
    "CVE-2014-4094",
    "CVE-2014-4095",
    "CVE-2014-4096",
    "CVE-2014-4097",
    "CVE-2014-4098",
    "CVE-2014-4099",
    "CVE-2014-4100",
    "CVE-2014-4101",
    "CVE-2014-4102",
    "CVE-2014-4103",
    "CVE-2014-4104",
    "CVE-2014-4105",
    "CVE-2014-4106",
    "CVE-2014-4107",
    "CVE-2014-4108",
    "CVE-2014-4109",
    "CVE-2014-4110",
    "CVE-2014-4111"
  );
  script_bugtraq_id(
    65601,
    69576,
    69578,
    69580,
    69581,
    69583,
    69584,
    69585,
    69587,
    69588,
    69589,
    69590,
    69591,
    69595,
    69596,
    69597,
    69598,
    69599,
    69600,
    69601,
    69602,
    69604,
    69605,
    69606,
    69607,
    69608,
    69609,
    69610,
    69611,
    69612,
    69613,
    69614,
    69615,
    69616,
    69617,
    69618,
    69619
  );
  script_osvdb_id(
    93005,
    111112,
    111113,
    111114,
    111115,
    111116,
    111117,
    111118,
    111119,
    111120,
    111121,
    111122,
    111123,
    111124,
    111125,
    111126,
    111127,
    111128,
    111129,
    111130,
    111131,
    111132,
    111133,
    111134,
    111135,
    111136,
    111137,
    111138,
    111139,
    111140,
    111141,
    111142,
    111143,
    111144,
    111145,
    111146,
    111147
  );
  script_xref(name:"CERT", value:"539289");
  script_xref(name:"MSFT", value:"MS14-052");

  script_name(english:"MS14-052: Cumulative Security Update for Internet Explorer (2977629)");
  script_summary(english:"Checks the version of Mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Internet Explorer (IE) Security Update
2977629.

The version of Internet Explorer installed on the remote host is
affected by multiple vulnerabilities, the majority of which are remote
code execution vulnerabilities. An attacker can exploit these by
convincing a user to visit a specially crafted web page.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-052");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Internet Explorer 6, 7, 8,
9, 10, and 11.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS14-052';
kb = '2977629';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / 2012 R2
  #
  # - Internet Explorer 11 with KB2919355 applied
  hotfix_is_vulnerable(os:"6.3", file:"Mshtml.dll", version:"11.0.9600.17278", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / 2012
  #
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.21207", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", file:"Mshtml.dll", version:"10.0.9200.17088", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  # - Internet Explorer 11 with KB2929437 applied
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"11.0.9600.17280", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.21207", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"10.0.9200.17088", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.20691", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"9.0.8112.16575", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.22777", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mshtml.dll", version:"8.0.7601.18571", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  #
  # - Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.20691", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"9.0.8112.16575", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.23619", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"8.0.6001.19561", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.23470", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mshtml.dll", version:"7.0.6002.19165", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # Windows 2003
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"8.0.6001.23619", min_version:"8.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"7.0.6000.21408", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.5413",  min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb)
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
