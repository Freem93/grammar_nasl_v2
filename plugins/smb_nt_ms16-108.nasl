#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93467);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/03/20 15:44:32 $");

  script_cve_id(
    "CVE-2015-6014",
    "CVE-2016-0138",
    "CVE-2016-3378",
    "CVE-2016-3379",
    "CVE-2016-3574",
    "CVE-2016-3575",
    "CVE-2016-3576",
    "CVE-2016-3577",
    "CVE-2016-3578",
    "CVE-2016-3579",
    "CVE-2016-3580",
    "CVE-2016-3581",
    "CVE-2016-3582",
    "CVE-2016-3583",
    "CVE-2016-3590",
    "CVE-2016-3591",
    "CVE-2016-3592",
    "CVE-2016-3593",
    "CVE-2016-3594",
    "CVE-2016-3595",
    "CVE-2016-3596"
  );
  script_bugtraq_id(
    81233,
    91908,
    91914,
    91921,
    91923,
    91924,
    91925,
    91927,
    91929,
    91931,
    91933,
    91934,
    91935,
    91936,
    91937,
    91939,
    91940,
    91942,
    92806,
    92833,
    92836
  );
  script_osvdb_id(
    133206,
    141724,
    141725,
    141726,
    141727,
    141728,
    141729,
    141730,
    141731,
    141732,
    141733,
    141734,
    141735,
    141736,
    141737,
    141738,
    141739,
    141740,
    144179,
    144180,
    144181
  );
  script_xref(name:"MSFT", value:"MS16-108");

  script_name(english:"MS16-108: Security Update for Microsoft Exchange Server (3185883)");
  script_summary(english:"Checks the version of ExSetup.exe.");

  script_set_attribute(attribute:"synopsis",value:
"The remote Microsoft Exchange Server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The remote Microsoft Exchange Server is missing a security update. It
is, therefore, affected by multiple vulnerabilities :

  - Multiple remote code execution vulnerabilities exist in
    the Oracle Outside In libraries. An unauthenticated,
    remote attacker can exploit these, via a specially
    crafted email, to execute arbitrary code.
    (CVE-2015-6014, CVE-2016-3575, CVE-2016-3581,
    CVE-2016-3582, CVE-2016-3583, CVE-2016-3591,
    CVE-2016-3592, CVE-2016-3593, CVE-2016-3594,
    CVE-2016-3595, CVE-2016-3596)

  - An unspecified information disclosure vulnerability
    exists in the Oracle Outside In libraries that allows an
    attacker to disclose sensitive information.
    (CVE-2016-3574)

  - Multiple denial of service vulnerabilities exists in the
    Oracle Outside In libraries. (CVE-2016-3576,
    CVE-2016-3577, CVE-2016-3578, CVE-2016-3579,
    CVE-2016-3580, CVE-2016-3590)

  - An information disclosure vulnerability exists due to
    improper parsing of certain unstructured file formats.
    An unauthenticated, remote attacker can exploit this,
    via a crafted email using 'send as' rights, to disclose
    confidential user information. (CVE-2016-0138)

  - An open redirect vulnerability exists due to improper
    handling of open redirect requests. An unauthenticated,
    remote attacker can exploit this, by convincing a user
    to click a specially crafted URL, to redirect the user
    to a malicious website that spoofs a legitimate one.
    (CVE-2016-3378)

  - An elevation of privilege vulnerability exists due to
    improper handling of meeting invitation requests. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted Outlook meeting invitation request,
    to gain elevated privileges. (CVE-2016-3379)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS16-108");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Exchange Server 2007,
2010, 2013, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/07/19");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS16-108';
kbs = make_list("3184711", "3184728", "3184736");

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

install = get_single_install(app_name:"Microsoft Exchange");

path = install["path"];
version = install["version"];
release = install["RELEASE"];
if (release != 80 && release != 140 && release != 150 && release != 151)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (!empty_or_null(install["SP"]))
  sp = install["SP"];
if (!empty_or_null(install["CU"]))
  cu = install["CU"];

if (((release == 150 || release == 151) && isnull(cu)) ||
   (release == 150 && cu != 4 && cu != 12 && cu != 13) ||
   (release == 151 && cu != 1 && cu != 2))
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (release == 80)
{
  kb = "3184711";
  if (!empty_or_null(sp) && sp == 3)
    fixedver = "8.3.485.1";
}
else if (release == 140)
{
  kb = "3184728";
  if (!empty_or_null(sp) && sp == 3)
    fixedver = "14.3.319.2";
}
else if (release == 150) # 2013 SP1 AKA CU4
{
  kb = "3184736";
  if (cu == 4)
    fixedver = "15.0.847.50";
  else if (cu == 12)
    fixedver = "15.0.1178.9";
  else if (cu == 13)
    fixedver = "15.0.1210.6";
}
else if (release == 151) # Exchange Server 2016
{
  kb = "3184736";
  if (cu == 1)
    fixedver = "15.1.396.37";
  else if (cu == 2)
    fixedver = "15.1.466.37";
}

if (fixedver && hotfix_is_vulnerable(path:hotfix_append_path(path:path, value:"Bin"), file:"ExSetup.exe", version:fixedver, bulletin:bulletin, kb:kb))
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
