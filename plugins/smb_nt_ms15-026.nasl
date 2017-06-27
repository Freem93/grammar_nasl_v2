#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81740);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id(
    "CVE-2015-1628",
    "CVE-2015-1629",
    "CVE-2015-1630",
    "CVE-2015-1631",
    "CVE-2015-1632"
  );
  script_bugtraq_id(72883, 72888, 72887, 72890, 72895);
  script_osvdb_id(119377, 119378, 119379, 119380, 119381);
  script_xref(name:"MSFT", value:"MS15-026");
  script_xref(name:"IAVA", value:"2015-A-0049");

  script_name(english:"MS15-026: Vulnerabilities in Microsoft Exchange Server Could Allow Elevation of Privilege (3040856)");
  script_summary(english:"Checks version of ExSetup.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Microsoft Exchange server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft Exchange server is missing a security update. It
is, therefore, affected by multiple vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exist due
    to improper sanitization of page content in Outlook Web
    App. An attacker can exploit these vulnerabilities by
    modifying properties within Outlook Web App and then 
    convincing a user browse to the targeted Outlook Web App
    site, resulting in the execution of arbitrary script
    code in the context of the current user. (CVE-2015-1628,
    CVE-2015-1629, CVE-2015-1630, CVE-2015-1632)

  - A spoofing vulnerability exists due to a failure to
    properly validate the meeting organizer's identity when
    accepting or modifying meeting requests. A remote
    attacker can exploit this issue to send forged meeting
    requests appearing to originate from a legitimate
    organizer. (CVE-2015-1631)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-026");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/03/10");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
port = kb_smb_transport();

bulletin = 'MS15-026';
kb = '3040856';
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

# Release is numeric version
version = get_kb_item_or_exit('SMB/Exchange/Version');
sp = int(get_kb_item('SMB/Exchange/SP'));

if (version != 150) # 2013
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

exch_root = get_kb_item_or_exit('SMB/Exchange/Path', exit_code:1);
# remove trailing slashes from path so it looks good when reporting
if(exch_root[strlen(exch_root) - 1] == "\")
  exch_root = substr(exch_root, 0, strlen(exch_root) - 2);

share     = hotfix_path2share(path:exch_root);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# If Exchange 2013 is installed, make sure it is CU4 (aka SP1) or CU7 before continuing
# set cu
cu = NULL;
if (version == 150)
{
  exe = hotfix_append_path(path:exch_root, value:"Bin\msexchangerepl.exe");
  ret = hotfix_get_fversion(path:exe);
  if (ret['error'] != HCF_OK)
  {
    hotfix_check_fversion_end();
    audit(AUDIT_FN_FAIL, 'hotfix_get_fversion');
  }
  exe_ver = join(ret['value'], sep:'.');

  if(exe_ver =~ "^15\.0\.847\.") cu = 4; # SP4
  if(exe_ver =~ "^15\.0\.1044\.") cu = 7; # CU7
  if (isnull(cu))
  {
    hotfix_check_fversion_end();
    audit(AUDIT_INST_VER_NOT_VULN, 'Exchange 2013', exe_ver);
  }
}

fixedver = NULL;

if (version == 150 && cu == 4) # 2013 SP1 AKA CU4
{
  fixedver = "15.0.847.38";
}
else if (version == 150 && cu == 7) # 2013 CU7
{
  fixedver = '15.0.1044.29';
}

if (hotfix_is_vulnerable(path:exch_root, file:"Bin\ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  set_kb_item(name:'www/0/XSS', value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
