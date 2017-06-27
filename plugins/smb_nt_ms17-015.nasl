#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97744);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/26 23:57:36 $");

  script_cve_id("CVE-2017-0110");
  script_bugtraq_id(96621);
  script_osvdb_id(153723);
  script_xref(name:"MSFT", value:"MS17-015");
  script_xref(name:"MSKB", value:"4012178");
  script_xref(name:"IAVA", value:"2017-A-0062");

  script_name(english:"MS17-015: Security Update for Microsoft Exchange Server (4013242)");
  script_summary(english:"Checks the version of ExSetup.exe.");

  script_set_attribute(attribute:"synopsis",value:
"The remote Microsoft Exchange Server is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The remote Microsoft Exchange Server is missing a security update. It
is, therefore, affected by an elevation of privilege vulnerability in
Outlook Web Access (OWA) due to improper handling of web requests. An
unauthenticated, remote attacker can exploit this issue, via a
specially crafted email containing a malicious link or attachment, to
execute arbitrary script code, inject content, or disclose sensitive
information.");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS17-015");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Exchange Server 2013 and
2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/15");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

bulletin = 'MS17-015';
kb = "4012178";
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

install = get_single_install(app_name:"Microsoft Exchange");

path = install["path"];
version = install["version"];
release = install["RELEASE"];

if (release != 150 && release != 151)
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (!empty_or_null(install["SP"]))
  sp = install["SP"];
if (!empty_or_null(install["CU"]))
  cu = install["CU"];

if (((release == 150 || release == 151) && isnull(cu)) ||
   (release == 150 && cu != 4 && cu != 14) ||
   (release == 151 && cu != 3))
  audit(AUDIT_INST_VER_NOT_VULN, 'Exchange', version);

if (release == 150) # 2013 SP1 AKA CU4
{
  if (cu == 4)
    fixedver = "15.0.847.53";
  else if (cu == 14)
    fixedver = "15.0.1236.6";
}
else if (release == 151) # Exchange Server 2016
{
  if (cu == 3)
    fixedver = "15.1.544.30";
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
