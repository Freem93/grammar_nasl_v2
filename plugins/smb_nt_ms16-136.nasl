#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94637);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2016-7249",
    "CVE-2016-7250",
    "CVE-2016-7251",
    "CVE-2016-7252",
    "CVE-2016-7253",
    "CVE-2016-7254"
  );
  script_bugtraq_id(
    94037,
    94043,
    94050,
    94056,
    94060,
    94061
  );
  script_osvdb_id(
    146899,
    146900,
    146901,
    146902,
    146903,
    146904
  );
  script_xref(name:"MSFT", value:"MS16-136");
  script_xref(name:"IAVA", value:"2016-A-0320");

  script_name(english:"MS16-136: Security Update for SQL Server (3199641)");
  script_summary(english:"Determines the version of the SQL Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist
    in the SQL RDBMS Engine due to improper handling of
    pointer casting. An authenticated, remote attacker can
    exploit these to gain elevated privileges.
    (CVE-2016-7249, CVE-2016-7250, CVE-2016-7254)

  - A cross-site scripting (XSS) vulnerability exists in
    the SQL server MDS API due to improper validation of a
    request parameter on the SQL server site. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted request, to execute arbitrary code
    in the user's browser session. (CVE-2016-7251)

  - An information disclosure vulnerability exists in
    Microsoft SQL Analysis Services due to improper
    validation of the FILESTREAM path. An authenticated,
    remote attacker can exploit this to disclose sensitive
    database and file information. (CVE-2016-7252)

  - An elevation of privilege vulnerability exists in the
    Microsoft SQL Server Engine due to improper checking by
    the SQL Server Agent of ACLs on atxcore.dll. An
    authenticated, remote attacker can exploit this to gain
    elevated privileges. (CVE-2016-7253)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-136");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2012, 2014, and
2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_enum_services.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 1433, "Services/mssql", 'Host/patch_management_checks');

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-136';
kbs = make_list(
  "3194714",
  "3194716",
  "3194717",
  "3194718",
  "3194719",
  "3194720",
  "3194721",
  "3194722",
  "3194724",
  "3194725"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

ver_list = get_kb_list("mssql/installs/*/SQLVersion");

if (isnull(ver_list)) audit(AUDIT_NOT_INST, "Microsoft SQL Server");

# Database Services Core Instance
foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");

  # continue if not SQL Server 2012, 2014, or 2016
  if (version !~ "^11\.0\." && version !~ "^12\.0\." && version !~ "^13\.0\.") continue;

  sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

  if (
    sqlpath &&
    # 2012 SP2 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.5388.0", min_version:"2011.110.5058.0", bulletin:bulletin, kb:'3194719') ||
    # 2012 SP2 CU
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.5676.0", min_version:"2011.110.5500.0", bulletin:bulletin, kb:'3194725') ||
    # 2012 SP3 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.6248.0", min_version:"2011.110.6020.0", bulletin:bulletin, kb:'3194721') ||
    # 2012 SP3 CU
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.6567.0", min_version:"2011.110.6300.0", bulletin:bulletin, kb:'3194724') ||
    # 2014 SP1 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2014.120.4232.0", min_version:"2014.120.4100.0", bulletin:bulletin, kb:'3194720') ||
    # 2014 SP1 CU
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2014.120.4487.0", min_version:"2014.120.4400.0", bulletin:bulletin, kb:'3194722') ||
    # 2014 SP2 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2014.120.5203.0", min_version:"2014.120.5000.0", bulletin:bulletin, kb:'3194714') ||
    # 2014 SP2 CU
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2014.120.5532.0", min_version:"2014.120.5400.0", bulletin:bulletin, kb:'3194718') ||
    # 2016 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2015.130.1722.0", min_version:"2015.130.1601.5", bulletin:bulletin, kb:'3194716') ||
    # 2016 CU
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2015.130.2186.6", min_version:"2015.130.2100.0", bulletin:bulletin, kb:'3194717')
  )
  {
    vuln++;
  }
}
hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:'www/0/XSS', value:TRUE); # CVE-2016-7251
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
