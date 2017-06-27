#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(79827);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/11 13:15:59 $");

  script_cve_id(
    "CVE-2014-6319",
    "CVE-2014-6325",
    "CVE-2014-6326",
    "CVE-2014-6336"
  );
  script_bugtraq_id(71437, 71440, 71441, 71442);
  script_osvdb_id(115655, 115656, 115657, 115658);
  script_xref(name:"MSFT", value:"MS14-075");

  script_name(english:"MS14-075: Vulnerabilities in Microsoft Exchange Server Could Allow Elevation of Privilege (3009712)");
  script_summary(english:"Checks the version of wsbexchange.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Exchange installed on the remote host is
affected by multiple vulnerabilities :

  - A token spoofing vulnerability exists due to Microsoft
    Outlook Web App (OWA) not properly validating request
    tokens. A remote attacker can exploit this vulnerability
    by convincing a user to visit a website with specially
    crafted content, allowing the attacker to send email
    that appears to come from a user other than the
    attacker. (CVE-2014-6319)

  - Multiple cross-site scripting vulnerabilities exist due
    to Microsoft Exchange not properly validating input. A
    remote attacker can exploit these vulnerabilities by
    convincing a user to click a specially crafted URL to
    the targeted Outlook Web App site. (CVE-2014-6325,
    CVE-2014-6326).

   - A spoofing vulnerability exists due to Microsoft
     Outlook Web App (OWA) not properly validating
     redirection tokens. An attacker can exploit this
     vulnerability to redirect a user to an arbitrary domain
     from a link that appears to originate from the user's
     domain. An attacker can also exploit this vulnerability
     to send email that appears to come from a user other
     than the attacker. (CVE-2014-6336).");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-075");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Exchange 2007 SP3, 2010
SP3, and 2013 SP1 / CU6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS14-075';
kbs = make_list(
  '3011140', # Exchange 2013 CU6 / SP1
  '2986475', # Exchange 2010 SP3
  '2996150'  # Exchange 2007 SP3
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

# Release is numeric version
version = get_kb_item_or_exit('SMB/Exchange/Version');
sp = int(get_kb_item('SMB/Exchange/SP'));

if (version != 80 && version != 140 && version != 150) # not 2007, 2010, 2013
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);
else if (version == 80 && sp != 3) # not 2007 SP3
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2007 SP' + sp);
else if (version == 140 && sp != 3) # not 2010 SP3
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', '2010 SP' + sp);

exch_root = get_kb_item_or_exit('SMB/Exchange/Path', exit_code:1);
exch_root = hotfix_append_path(path:exch_root, value:"\");
share     = hotfix_path2share(path:exch_root);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# If Exchange 2013 is installed, make sure it is CU4 (Aka SP1) or CU6 before continuing
# set cu
cu = NULL;
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

  if(exe_ver =~ "^15\.0\.847\.") cu = 4;
  if(exe_ver =~ "^15\.0\.995\.") cu = 6;
  if (isnull(cu))
  {
    hotfix_check_fversion_end();
    audit(AUDIT_INST_VER_NOT_VULN, 'Exchange 2013', exe_ver);
  }
}

if (version == 80) # 2007 SP3
{
  kb = '2996150';
  fixedver = "8.3.389.2";
}
else if (version == 140) # 2010 SP3
{
  kb = '2986475';
  fixedver = "14.3.224.2";
}
else if (version == 150 && cu == 4) # 2013 SP1 AKA CU4
{
  kb = '3011140';
  fixedver = "15.0.847.34";
}
else if (version == 150 && cu == 6) # 2013 CU6
{
  kb = '3011140';
  fixedver = "15.0.995.32";
}

if (hotfix_is_vulnerable(path:exch_root, file:"Bin\wsbexchange.exe", version:fixedver, bulletin:bulletin, kb:kb))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  set_kb_item(name:'www/0/XSS', value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
