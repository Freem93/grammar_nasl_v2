#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84738);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 15:02:06 $");

  script_cve_id(
    "CVE-2015-1761",
    "CVE-2015-1762",
    "CVE-2015-1763"
  );
  script_osvdb_id(
    124764,
    124765,
    124766
  );
  script_xref(name:"MSFT", value:"MS15-058");
  script_xref(name:"IAVA", value:"2015-A-0171");

  script_name(english:"MS15-058: Vulnerabilities in SQL Server Could Allow Remote Code Execution (3065718)");
  script_summary(english:"Determines the version of the SQL Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL Server installation is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server installation is affected by multiple
vulnerabilities :

  - A privilege escalation vulnerability exists due to the
    casting of pointers to an incorrect class. An
    authenticated, remote attacker can exploit this, via a
    specially crafted SQL query, to gain elevated
    privileges. (CVE-2015-1761)

  - A remote code execution vulnerability exists due to
    incorrect handling of internal function calls to
    uninitialized memory. An attacker can exploit this, via
    a specially crafted SQL query on an affected SQL server
    that has special permission settings (such as VIEW
    SERVER STATE) turned on, to execute arbitrary code.
    (CVE-2015-1762)

  - A remote code execution vulnerability exists due to
    incorrect handling of internal function calls to
    uninitialized memory. An authenticated, remote attacker
    can exploit this, via a specially crafted SQL query
    designed to execute a virtual function from a wrong
    address, to execute arbitrary code. (CVE-2015-1762)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-058");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2008, 2008 R2,
2012, and 2014.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

bulletin = 'MS15-058';
kbs = make_list(
  "3045305",
  "3045303",
  "3045311",
  "3045308",
  "3045313",
  "3045312",
  "3045316",
  "3045314",
  "3045318",
  "3045317",
  "3045321",
  "3045319",
  "3045324",
  "3045323"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

ver_list = get_kb_list("mssql/installs/*/SQLVersion");

if (isnull(ver_list))
   audit(AUDIT_NOT_INST, "Microsoft SQL Server");

# Database Services Core Instance
foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");
  if (version !~ "^10\.0\." && version !~ "^10\.50\." && version !~ "^11\.0\." && version !~ "^12\.0\.") continue;

  sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

  if (
    sqlpath &&

    # 2014 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2014.120.2269.0", min_version:"2014.120.2000.0", bulletin:bulletin, kb:'3045324') ||
    # 2014 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2014.120.2548.0", min_version:"2014.120.2300.0", bulletin:bulletin, kb:'3045323') ||
 
    # 2012 SP2 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.5343.0", min_version:"2011.110.5058.0", bulletin:bulletin, kb:'3045321') ||
    # 2012 SP2 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.5613.0", min_version:"2011.110.5532.0", bulletin:bulletin, kb:'3045319') ||
    # 2012 SP1 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.3156.0", min_version:"2011.110.3000.0", bulletin:bulletin, kb:'3045318') ||
    # 2012 SP1 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.3513.0", min_version:"2011.110.3300.0", bulletin:bulletin, kb:'3045317') ||

    # 2008 R2 SP3 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2009.100.6220.0", min_version:"2009.100.6000.0", bulletin:bulletin, kb:'3045316') ||
    # 2008 R2 SP3 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2009.100.6529.0", min_version:"2009.100.6500.0", bulletin:bulletin, kb:'3045314') ||
    # 2008 R2 SP2 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2009.100.4042.0", min_version:"2009.100.4000.0", bulletin:bulletin, kb:'3045313') ||
    # 2008 R2 SP2 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2009.100.4339.0", min_version:"2009.100.4251.0", bulletin:bulletin, kb:'3045312') ||

    # 2008 SP4 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2007.100.6241.0", min_version:"2007.100.6000.0", bulletin:bulletin, kb:'3045311') ||
    # 2008 SP4 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2007.100.6535.0", min_version:"2007.100.6500.0", bulletin:bulletin, kb:'3045308') ||
    # 2008 SP3 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2007.100.5538.0", min_version:"2007.100.5500.0", bulletin:bulletin, kb:'3045305') ||
    # 2008 SP3 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2007.100.5890.0", min_version:"2007.100.5750.0", bulletin:bulletin, kb:'3045303')
  )
  {
    vuln++;
  }
}
hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
