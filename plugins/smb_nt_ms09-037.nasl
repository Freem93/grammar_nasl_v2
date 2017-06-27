#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40556);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2008-0015", "CVE-2008-0020", "CVE-2009-0901", "CVE-2009-2493", "CVE-2009-2494");
  script_bugtraq_id(35558, 35585, 35828, 35832, 35982);
  script_osvdb_id(55651, 56272, 56696, 56698, 56910);
  script_xref(name:"MSFT", value:"MS09-037");
  script_xref(name:"IAVA", value:"2009-A-0067");
  script_xref(name:"CERT", value:"180513");
  script_xref(name:"CERT", value:"456745");
  script_xref(name:"EDB-ID", value:"9108");
  script_xref(name:"EDB-ID", value:"16615");

  script_name(english:"MS09-037: Vulnerabilities in Microsoft Active Template Library (ATL) Could Allow Remote Code Execution (973908)");
  script_summary(english:"Checks version of various files");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Active Template Library.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of the Microsoft Active
Template Library (ATL), included as part of Visual Studio or Visual C++,
that is affected by multiple vulnerabilities :

  - A remote code execution issue affects the Microsoft
    Video ActiveX Control due to the a flaw in the function
    'CComVariant::ReadFromStream' used in the ATL header,
    which fails to properly restrict untrusted data read
    from a stream. (CVE-2008-0015)

  - A remote code execution issue exists in the Microsoft
    Active Template Library due to an error in the 'Load'
    method of the 'IPersistStreamInit' interface, which
    could allow calls to 'memcpy' with untrusted data.
    (CVE-2008-0020)

  - An issue in the ATL headers could allow an attacker to
    force VariantClear to be called on a VARIANT that has
    not been correctly initialized and, by supplying a
    corrupt stream, to execute arbitrary code.
    (CVE-2009-0901)

  - Unsafe usage of 'OleLoadFromStream' could allow
    instantiation of arbitrary objects which can bypass
    related security policy, such as kill bits within
    Internet Explorer. (CVE-2009-2493)

  - A bug in the ATL header could allow reading a variant
    from a stream and leaving the variant type read with
    an invalid variant, which could be leveraged by an
    attacker to execute arbitrary code remotely.
    (CVE-2009-2494)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-037");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft DirectShow (msvidctl.dll) MPEG-2 Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 119, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS09-037';
kbs = make_list("973354", "973507", "973540", "973815", "973869");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

programfiles = hotfix_get_programfilesdir();
if (!programfiles) exit(1, "Can't determine location of Program Files.");

if (tolower(programfiles[0]) != tolower(rootfile[0]))
{
  share = hotfix_path2share(path:programfiles);
  if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);
}

commonfiles = hotfix_get_officecommonfilesdir();
if (!commonfiles) exit(1, "Can't determine location of Common Files.");

vuln = 0;

# Media Player.
if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Wmp.dll", version:"11.0.6002.22172", min_version:"11.0.6002.20000", dir:"\System32", bulletin:bulletin, kb:'973540') ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Wmp.dll", version:"11.0.6002.18065",                                dir:"\System32", bulletin:bulletin, kb:'973540') ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Wmp.dll", version:"11.0.6001.7114",  min_version:"11.0.6001.7100",  dir:"\System32", bulletin:bulletin, kb:'973540') ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Wmp.dll", version:"11.0.6001.7007",                                 dir:"\System32", bulletin:bulletin, kb:'973540') ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Wmp.dll", version:"11.0.6000.6511",  min_version:"11.0.6000.6500",  dir:"\System32", bulletin:bulletin, kb:'973540') ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Wmp.dll", version:"11.0.6000.6352",                                 dir:"\System32", bulletin:bulletin, kb:'973540') ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Wmp.dll", version:"10.0.0.4006",                                    dir:"\System32", bulletin:bulletin, kb:'973540') ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Wmp.dll", version:"9.0.0.4507",                                     dir:"\System32", bulletin:bulletin, kb:'973540') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Wmp.dll", version:"11.0.5721.5268",  min_version:"11.0.0.0",        dir:"\System32", bulletin:bulletin, kb:'973540') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Wmp.dll", version:"10.0.0.4006",                                    dir:"\System32", bulletin:bulletin, kb:'973540') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Wmp.dll", version:"9.0.0.3271",                                     dir:"\System32", bulletin:bulletin, kb:'973540') ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Wmp.dll", version:"9.0.0.3364",                                     dir:"\System32", bulletin:bulletin, kb:'973540')
) vuln++;


# ATL.
if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Atl.dll", version:"3.5.2284.2",                               dir:"\System32", bulletin:bulletin, kb:'973507') ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Atl.dll", version:"3.5.2284.2",                               dir:"\System32", bulletin:bulletin, kb:'973507') ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Atl.dll", version:"3.5.2284.2",                               dir:"\System32", bulletin:bulletin, kb:'973507') ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Atl.dll", version:"3.5.2284.2", dir:"\System32", bulletin:bulletin, kb:'973507') ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Atl.dll", version:"3.5.2284.2", dir:"\System32", bulletin:bulletin, kb:'973507') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Atl.dll", version:"3.5.2284.2", dir:"\System32", bulletin:bulletin, kb:'973507') ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",       file:"Atl.dll", version:"3.0.9793.0", dir:"\System32", bulletin:bulletin, kb:'973507')
) vuln++;


# MSWebDVD ActiveX Control.
if (
  # Vista / Windows Server 2008
  #
  # empty

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Mswebdvd.dll", version:"6.5.3790.4564", dir:"\System32", bulletin:bulletin, kb:'973815') ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mswebdvd.dll", version:"6.5.2600.5848", dir:"\System32", bulletin:bulletin, kb:'973815') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mswebdvd.dll", version:"6.5.2600.3603", dir:"\System32", bulletin:bulletin, kb:'973815')

  # Windows 2000
  #
  # empty
) vuln++;


# Outlook Express.
NetUseDel(close:FALSE);
if (
  # Vista / Windows Server 2008
  #
  # empty

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Msoe.dll", version:"6.0.3790.4548",                         dir:"\Outlook Express", path:programfiles, bulletin:bulletin, kb:'973354') ||

  # Windows XP
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Msoe.dll", version:"6.0.2900.5843",                         dir:"\Outlook Express", path:programfiles, bulletin:bulletin, kb:'973354') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x64", file:"Msoe.dll", version:"6.0.3790.4548",                         dir:"\Outlook Express", path:programfiles, bulletin:bulletin, kb:'973354') ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Msoe.dll", version:"6.0.2900.3598",                         dir:"\Outlook Express", path:programfiles, bulletin:bulletin, kb:'973354') ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0",                   file:"Msoe.dll", version:"6.0.2800.1983",  min_version:"6.0.0.0", dir:"\Outlook Express", path:programfiles, bulletin:bulletin, kb:'973354') ||
  hotfix_is_vulnerable(os:"5.0",                   file:"Msoe.dll", version:"5.50.5003.1000",                        dir:"\Outlook Express", path:programfiles, bulletin:bulletin, kb:'973354')
) vuln++;


# DHTML Editing Component ActiveX control/
if  (!commonfiles)
{
  hotfix_check_fversion_end();
  exit(1, "Can't determine location of Common Files.");
}
if (typeof(commonfiles) != 'array')
{
  temp = commonfiles;
  commonfiles = make_array('commonfiles', commonfiles);
}
checkeddirs = make_array();
NetUseDel(close:FALSE);
foreach ver (keys(commonfiles))
{
  dir = commonfiles[ver];
  if (checkeddirs[dir]) continue;
  checkeddirs[dir] = 1;
  if (
    # Vista / Windows Server 2008
    #
    # empty

    # Windows 2003
    hotfix_is_vulnerable(os:"5.2", sp:2, file:"Dhtmled.ocx", version:"6.1.0.9247", dir:"\Microsoft Shared\Triedit", path:dir, bulletin:bulletin, kb:'973869') ||

    # Windows XP
    hotfix_is_vulnerable(os:"5.1", sp:3, file:"Dhtmled.ocx", version:"6.1.0.9247", dir:"\Microsoft Shared\Triedit", path:dir, bulletin:bulletin, kb:'973869') ||
    hotfix_is_vulnerable(os:"5.1", sp:2, file:"Dhtmled.ocx", version:"6.1.0.9247", dir:"\Microsoft Shared\Triedit", path:dir, bulletin:bulletin, kb:'973869') ||

    # Windows 2000
    hotfix_is_vulnerable(os:"5.0",       file:"Dhtmled.ocx", version:"6.1.0.9234", dir:"\Microsoft Shared\Triedit", path:dir, bulletin:bulletin, kb:'973869')
  ) vuln++;
}

if (vuln)
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
