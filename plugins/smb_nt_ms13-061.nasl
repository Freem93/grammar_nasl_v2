#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69326);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-2393", "CVE-2013-3776", "CVE-2013-3781");
  script_bugtraq_id(59129, 61232, 61234);
  script_osvdb_id(92390, 95275, 95276);
  script_xref(name:"MSFT", value:"MS13-061");

  script_name(english:"MS13-061: Vulnerabilities in Microsoft Exchange Server Could Allow Remote Code Execution (2876063)");
  script_summary(english:"Checks version of transcodingservice.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote mail server has multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Microsoft Exchange installed on the remote host uses a
version of the Oracle Outside In libraries, which are affected by the
following vulnerabilities :

  - Two unspecified code execution vulnerabilities exist in
    the WebReady Document Viewing feature of Outlook Web
    Access. (CVE-2013-2393, CVE-2013-3776)

  - An unspecified denial of service vulnerability exists in
    the Data Loss Protection feature.  This vulnerability
    only affects Exchange 2013. (CVE-2013-3781)

These vulnerabilities can be exploited when a user views a maliciously
crafted file in Outlook Web Access in a browser."
  );
  # http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18c7ab23");
  # http://www.oracle.com/technetwork/topics/security/cpujuly2013-1899826.html#AppendixFMW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10faec64");
  # http://blogs.technet.com/b/exchange/archive/2013/08/14/exchange-2013-security-update-ms13-061-status-update.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae8ba636");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-061");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Exchange 2007 SP3, 2010 SP2
/ SP3, and 2013 CU2 and CU3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS13-061';
kbs = make_list(
  '2866475', # 2010 SP3
  '2873746', # 2007 SP3
  '2874216'  # 2010 SP2, 2013 CU1 & CU2
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

version = get_kb_item_or_exit('SMB/Exchange/Version');
sp = int(get_kb_item('SMB/Exchange/SP'));

# bail out if one of the following affected configurations is not seen
if (version != 80 && version != 140 && version != 150) # not 2007, 2010
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);
else if (version == 80 && sp != 3) # not 2007 SP3
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2007 SP' + sp);
else if (version == 140 && sp != 2 && sp != 3) # not 2010 SP2 or SP3
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2010 SP' + sp);
else if (version == 150 && sp != 0) # not 2013 CU1 or CU2 (no SP)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2013 SP' + sp);

exch_root = get_kb_item_or_exit('SMB/Exchange/Path', exit_code:1);
if (exch_root[strlen(exch_root) - 1] != "\") # add a trailing backslash if necessary
  exch_root += "\";
share = hotfix_path2share(path:exch_root);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (version == 80 && sp == 3) # 2007 SP3
  kb = '2873746';
else if (version == 140 && sp == 2) # 2010 SP2
  kb = '2874216';
else if (version == 140 && sp == 3) # 2010 SP3
  kb = '2866475';
else if (version == 150) # 2013 CU1 and CU2
  kb = '2874216';

# If Exchange 2013 is installed, make sure it is CU1 or CU2 before continuing
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
    exe_ver !~ "^15\.0\.620\." && # 2013 CU1
    exe_ver !~ "^15\.0\.712\."    # 2013 CU2
  )
  {
    hotfix_check_fversion_end();
    audit(AUDIT_INST_VER_NOT_VULN, 'Exchange 2013', exe_ver);
  }
}

ooi_path = exch_root + "ClientAccess\Owa\Bin\DocumentViewing";
file = 'vshwp2.dll';

if (hotfix_is_vulnerable(path:ooi_path, file:file, version:'8.3.7.314', bulletin:bulletin, kb:kb))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
