#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85335);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/16 04:44:42 $");

  script_cve_id(
    "CVE-2015-2434",
    "CVE-2015-2440",
    "CVE-2015-2471"
  );
  script_bugtraq_id(
    76229,
    76232,
    76257
  );
  script_osvdb_id(
    125990,
    125991,
    125992
  );
  script_xref(name:"MSFT", value:"MS15-084");
  script_xref(name:"IAVB", value:"2015-B-0098");

  script_name(english:"MS15-084: Vulnerabilities in XML Core Services Could Allow Information Disclosure (3080129)");
  script_summary(english:"Checks the file version of msxml5.dll and msxml6.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple information disclosure
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Microsoft XML Core
Services (MSXML) that is affected by multiple information disclosure
vulnerabilities :

  - An information disclosure vulnerability exists in XML
    Core Services (MSXML) due to the use of Secure Sockets
    Layer (SSL) 2.0. A man-in-the-middle attacker can
    exploit this vulnerability by forcing an encrypted SSL
    2.0 session and then decrypting the resulting network
    traffic. (CVE-2015-2434, CVE-2015-2471)

  - An information disclosure vulnerability exists in XML
    Core Services (MSXML) due to exposing sensitive memory
    addresses. A remote attacker, using a specially crafted
    website, can exploit this to bypass ASLR and gain access
    to private data. (CVE-2015-2440)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/ms15-084.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, 2012 R2, RT, RT 8.1, Office 2007 SP3, and
InfoPath 2007 SP3.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

bulletin = 'MS15-084';
kbs = make_list("2825645", "3076895");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

vuln = 0;

info_path = get_kb_item("SMB/Office/InfoPath/12.0/ProductPath");
office_vers = hotfix_check_office_version();

if (office_vers["12.0"] || info_path)
{
  path = hotfix_get_officecommonfilesdir(officever:"12.0") + "\Microsoft Office\Office12";
  if (path)
  {
    vuln += hotfix_is_vulnerable(path:path, file:"msxml5.dll", version:"5.20.1104.0", min_version:"5.0.0.0", bulletin:bulletin, kb:'2825645');
  }
}

affected_range = TRUE;
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0)
  affected_range = FALSE;

if (!affected_range && !vuln) audit(AUDIT_OS_SP_NOT_VULN);

if (affected_range)
{
  share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

  if (
    # 8.1 / 2012 R2
    hotfix_is_vulnerable(os:"6.3", sp:0, file:"msxml6.dll", version:"6.30.9600.17931", min_version:"6.30.9600.16000", dir:"\system32", bulletin:bulletin, kb:'3076895') ||

    # 8.0 / 2012
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"msxml6.dll", version:"6.30.9200.21548", min_version:"6.30.9200.20000", dir:"\system32", bulletin:bulletin, kb:'3076895') ||
    hotfix_is_vulnerable(os:"6.2", sp:0, file:"msxml6.dll", version:"6.30.9200.17436", min_version:"6.30.9200.16000", dir:"\system32", bulletin:bulletin, kb:'3076895') ||

    # 7 / 2008 R2
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"msxml6.dll", version:"6.30.7601.23126", min_version:"6.30.7601.22000", dir:"\system32", bulletin:bulletin, kb:'3076895') ||
    hotfix_is_vulnerable(os:"6.1", sp:1, file:"msxml6.dll", version:"6.30.7601.18923", min_version:"6.30.7600.18000", dir:"\system32", bulletin:bulletin, kb:'3076895') ||

    # Vista / 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"msxml6.dll", version:"6.20.5008.0", dir:"\system32", bulletin:bulletin, kb:'3076895')
    ) vuln++;
}

if(vuln)
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
