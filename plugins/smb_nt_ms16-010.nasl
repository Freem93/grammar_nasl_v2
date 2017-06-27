#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87895);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/11 13:15:59 $");

  script_cve_id(
    "CVE-2016-0029",
    "CVE-2016-0030",
    "CVE-2016-0031",
    "CVE-2016-0032"
  );
  script_bugtraq_id(
    79884,
    79888,
    79889,
    79890
  );
  script_osvdb_id(
    132786,
    132787,
    132788,
    132789
  );
  script_xref(name:"MSFT", value:"MS16-010");

  script_name(english:"MS16-010: Security Update in Microsoft Exchange Server to Address Spoofing (3124557)");
  script_summary(english:"Checks the version of ExSetup.exe.");

  script_set_attribute(attribute:"synopsis",value:
"The remote Microsoft Exchange server is affected by multiple spoofing
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The remote Microsoft Exchange server is missing a security update. It
is, therefore, affected by multiple spoofing vulnerabilities in
Outlook Web Access (OWA) due to a failure to properly handle web
requests. An attacker can exploit these vulnerabilities, via a crafted
email containing a malicious link, to redirect the user to a website
of the attacker's choosing.");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS16-010");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Exchange 2013 and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/01/12");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/13");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ms_bulletin_checks_possible.nasl", "microsoft_exchange_installed.nbin");
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

bulletin = 'MS16-010';
kb = '3124557';
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

install = get_single_install(app_name:"Microsoft Exchange");

path = install["path"];
version = install["version"];
release = install["RELEASE"];
if (release != 150 && release != 151)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);
cu = install["CU"];

if (isnull(cu) ||
   (release == 150 && cu != 4 && cu != 10 && cu != 11) ||
   (release == 151 && cu != 0))
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (release == 150 && cu == 4) # 2013 SP1 AKA CU4
{
  fixedver = "15.0.847.45";
}
else if (release == 150 && cu == 10) # 2013 CU10
{
  fixedver = '15.0.1130.10';
}
else if (release == 150 && cu == 11) # 2013 CU11
{
  fixedver = '15.0.1156.8';
}
else if (release == 151 && cu == 0) # Exchange Server 2016
{
  fixedver = '15.1.225.45';
}

if (hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb))
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
