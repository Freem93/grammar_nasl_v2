#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66417);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id(
    "CVE-2013-1316",
    "CVE-2013-1317",
    "CVE-2013-1318",
    "CVE-2013-1319",
    "CVE-2013-1320",
    "CVE-2013-1321",
    "CVE-2013-1322",
    "CVE-2013-1323",
    "CVE-2013-1327",
    "CVE-2013-1328",
    "CVE-2013-1329"
  );
  script_bugtraq_id(
    59761,
    59762,
    59763,
    59764,
    59766,
    59767,
    59768,
    59769,
    59770,
    58771,
    59772
  );
  script_osvdb_id(
    93304,
    93305,
    93306,
    93307,
    93308,
    93309,
    93310,
    93311,
    93312,
    93313,
    93314
  );
  script_xref(name:"MSFT", value:"MS13-042");

  script_name(english:"MS13-042: Vulnerabilities in Microsoft Publisher Could Allow Remote Code Execution (2830397)");
  script_summary(english:"Checks the version of Publisher");

  script_set_attribute(attribute:"synopsis", value:
"Microsoft Publisher, a component of Microsoft Office installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Publisher component of Microsoft Office installed on the remote
host is affected by multiple vulnerabilities :

  - The application has a negative value allocation
    vulnerability. (CVE-2013-1316)

  - The application has an integer overflow vulnerability.
    (CVE-2013-1317)

  - The application has a corrupt interface pointer
    vulnerability. (CVE-2013-1318)

  - The application has a return value handling
    vulnerability. (CVE-2013-1319)

  - The application has a buffer overflow vulnerability.
    (CVE-2013-1320)

  - The application has a return value validation
    vulnerability. (CVE-2013-1321)

  - The application has an invalid range check
    vulnerability. (CVE-2013-1322)

  - The application has an incorrect NULL value handling
    vulnerability. (CVE-2013-1323)

  - The application has a signed integer vulnerability.
    (CVE-2013-1327)

  - The application has a pointer handling vulnerability.
    (CVE-2013-1328)

  - The application has a buffer underflow vulnerability.
    (CVE-2013-1329)

A remote attacker could exploit these by tricking a user into opening
a specially crafted Publisher file, resulting in remote code
execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-042");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Publisher 2003
SP3, 2007 SP3, and 2010 SP1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS13-042';
kbs = make_list("2810047", "2597971", "2553147");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

installs = get_kb_list_or_exit("SMB/Office/Publisher/*/ProductPath");
vuln = FALSE;
foreach install (keys(installs))
{
  version = install - 'SMB/Office/Publisher/' - '/ProductPath';
  path = installs[install];
  if (isnull(path)) path = 'n/a';

  v = split(version, sep:'.', keep:FALSE);
  for (i = 0; i < max_index(v); i++)
    v[i] = int(v[i]);

  kb = "";
  # Office 2003 SP3
  if (v[0] == 11 && v[1] == 0 && (v[2] >= 8166 && v[2] < 8402))
  {
    office_sp = get_kb_item("SMB/Office/2003/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      vuln = TRUE;
      info = '\n  Product           : Publisher 2003'+
             '\n  File              : '+path+
             '\n  Installed version : '+version+
             '\n  Fixed version     : 11.0.8402.0\n';
      kb = "2810047";
    }
  }
  # Office 2007 SP3
  else if (v[0] == 12 && v[1] == 0 &&
           ((v[2] > 6606 || (v[2] == 6606 && v[3] >= 1000)) &&
            (v[2] < 6676 || (v[2] == 6676 && v[3] < 5000))))
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if(!isnull(office_sp) && (office_sp == 3))
    {
      vuln = TRUE;
      info = '\n  Product           : Publisher 2007'+
             '\n  File              : '+path+
             '\n  Installed version : '+version+
             '\n  Fixed version     : 12.0.6676.5000\n';
      kb = "2597971";
    }
  }
  # Office 2010 SP1
  else if (v[0] == 14 && v[1] == 0 &&
           ((v[2] > 6026 || (v[2] == 6026 && v[3] >= 1000)) &&
           (v[2] < 6137 || (v[2] == 6137 && v[3] < 5000))))
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 1)
    {
      vuln = TRUE;
      info = '\n  Product           : Publisher 2010'+
             '\n  File              : '+path+
             '\n  Installed version : '+version+
             '\n  Fixed version     : 14.0.6137.5000\n';
      kb = "2553147";
    }
  }
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_add_report(info, bulletin:bulletin, kb:kb);
  hotfix_security_hole();
  hotfix_check_fversion_end();

  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
