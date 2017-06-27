#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91612);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/09/26 14:31:38 $");

  script_cve_id(
    "CVE-2015-6013",
    "CVE-2015-6014",
    "CVE-2015-6015",
    "CVE-2016-0028"
  );
  script_bugtraq_id(
    81227,
    81233,
    81243,
    91115
  );
  script_osvdb_id(
    133206,
    133207,
    138339
  );
  script_xref(name:"MSFT", value:"MS16-079");
  script_xref(name:"CERT", value:"916896");

  script_name(english:"MS16-079: Security Update for Microsoft Exchange Server (3160339)");
  script_summary(english:"Checks the version of ExSetup.exe.");

  script_set_attribute(attribute:"synopsis",value:
"The remote Microsoft Exchange Server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The remote Microsoft Exchange Server is missing a security update. It
is, therefore, affected by multiple vulnerabilities :

  - Multiple stack buffer overflow conditions exist in the
    Oracle Outside In subcomponent due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit these, via a crafted file,
    to cause a denial of service condition or the execution
    of arbitrary code. (CVE-2015-6013, CVE-2015-6014,
    CVE-2015-6015)

  - An email filter bypass flaw exists in the parsing of
    HTML messages. An unauthenticated, remote attacker can
    exploit this, via specially crafted URLs in OWA messages,
    to identify, fingerprint, and track a user online if the
    user views email using Outlook Web Access.
    (CVE-2016-0028)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS16-079");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Exchange Server 2007,
2010, 2013, and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/15");

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

bulletin = 'MS16-079';
kbs = make_list('3151086', '3151097', '3150501');

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
   (release == 150 && cu != 4 && cu != 11 && cu != 12) ||
   (release == 151 && cu != 0 && cu != 1))
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (release == 80)
{
  kb = "3151086";
  if (!empty_or_null(sp) && sp == 3)
    fixedver = "8.3.468.0";
}
else if (release == 140)
{
  kb = "3151097";
  if (!empty_or_null(sp) && sp == 3)
    fixedver = "14.3.301.0";
}
else if (release == 150) # 2013 SP1 AKA CU4
{
  kb = "3150501";
  if (cu == 4)
    fixedver = "15.0.847.47";
  else if (cu == 11)
    fixedver = "15.0.1156.10";
  else if (cu == 12)
    fixedver = "15.0.1178.6";
}
else if (release == 151) # Exchange Server 2016
{
  kb = "3150501";
  if (cu == 0)
    fixedver = "15.1.225.49";
  else if (cu == 1)
    fixedver = "15.1.396.33";
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
