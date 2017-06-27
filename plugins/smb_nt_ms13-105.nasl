#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71320);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 18:02:19 $");

  script_cve_id(
    "CVE-2013-1330",
    "CVE-2013-5072",
    "CVE-2013-5763",
    "CVE-2013-5791"
  );
  script_bugtraq_id(62221, 63076, 63741, 64085);
  script_osvdb_id(97118, 98467, 98894, 100771);
  script_xref(name:"CERT", value:"953241");
  script_xref(name:"CERT", value:"959313");
  script_xref(name:"EDB-ID", value:"31222");
  script_xref(name:"IAVA", value:"2013-A-0231");
  script_xref(name:"MSFT", value:"MS13-105");

  script_name(english:"MS13-105: Vulnerabilities in Microsoft Exchange Server Could Allow Remote Code Execution (2915705)");
  script_summary(english:"Checks version of vshwp2.dll.");

  script_set_attribute(attribute:"synopsis", value:"The remote mail server has multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Exchange installed on the host is affected by
the following vulnerabilities :

  - A code execution vulnerability exists that could allow
    an attacker to execute arbitrary code in the context of
    the OWA service account. (CVE-2013-1330)

  - A cross-site scripting vulnerability exists in OWA in
    which an attacker could elevate their privileges and run
    a script in the context of the current user.
    (CVE-2013-5072)

  - Two code execution vulnerabilities exist in the WebReady
    Document Viewing feature of Outlook Web Access. Code
    execution is limited to the LocalService account.  In
    addition, a denial of service vulnerability exists in
    the DLP feature of Exchange 2013. (CVE-2013-5763,
    CVE-2013-5791)"
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-105/");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Exchange 2007 SP3, 2010 SP2
and SP3, 2013 CU2 and CU3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

port = kb_smb_transport();

bulletin = 'MS13-105';
kbs = make_list(
  '2880833', # Exchange 2013 CU2 & CU3
  '2905616', # Exchange 2010 SP3 - Rollup 4
  '2903911', # Exchange 2007 SP3 - Rollup 12
  '2903903'  # Exchange 2010 SP2 - Rollup 8
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');

version = get_kb_item_or_exit('SMB/Exchange/Version');
sp = int(get_kb_item('SMB/Exchange/SP'));

# bail out if one of the following affected configurations is not seen
if (version != 80 && version != 140 && version != 150) # not 2007, 2010
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);
else if (version == 80 && sp != 3) # not 2007 SP3
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2007 SP' + sp);
else if (version == 140 && sp != 2 && sp != 3) # not 2010 SP2 or SP3
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2010 SP' + sp);
else if (version == 150 && sp != 0) # not 2013 CU2 or CU3 (no SP)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2013 SP' + sp);

exch_root = get_kb_item_or_exit('SMB/Exchange/Path', exit_code:1);
if (exch_root[strlen(exch_root) - 1] != "\") # add a trailing backslash if necessary
  exch_root += "\";
share = hotfix_path2share(path:exch_root);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (version == 80 && sp == 3) # 2007 SP3
  kb = '2903911';
else if (version == 140 && sp == 2) # 2010 SP2
  kb = '2903903';
else if (version == 140 && sp == 3) # 2010 SP3
  kb = '2905616';
else if (version == 150) # 2013 CU2 and CU3
  kb = '2880833';

# If Exchange 2013 is installed, make sure it is CU2 or CU3 before continuing
if (version == 150)
{
  exe = exch_root + "Bin\msexchangerepl.exe";
  ret = hotfix_get_fversion(path:exe);
  if (ret['error'] != HCF_OK)
  {
    hotfix_check_fversion_end();
    audit(AUDIT_FN_FAIL, 'hotfix_get_fversion');
  }
  exe_ver = join(ret['value'], sep:'.');

  if (
    exe_ver !~ "^15\.0\.712\." && # 2013 CU2
    exe_ver !~ "^15\.0\.775\."    # 2013 CU3
  )
  {
    hotfix_check_fversion_end();
    audit(AUDIT_INST_VER_NOT_VULN, 'Exchange 2013', exe_ver);
  }
}

ooi_path = exch_root + "ClientAccess\Owa\Bin\DocumentViewing";
file = 'vshwp2.dll';

if (hotfix_is_vulnerable(path:ooi_path, file:file, version:'8.4.1.18', bulletin:bulletin, kb:kb))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
