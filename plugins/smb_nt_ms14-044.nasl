#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77162);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/01 15:02:06 $");

  script_cve_id("CVE-2014-1820", "CVE-2014-4061");
  script_bugtraq_id(69071, 69088);
  script_osvdb_id(109932, 109933);
  script_xref(name:"MSFT", value:"MS14-044");
  script_xref(name:"IAVA", value:"2014-A-0126");

  script_name(english:"MS14-044: Vulnerability in SQL Server Could Allow Elevation of Privilege (2984340)");
  script_summary(english:"Determines the version of the SQL Server.");

  script_set_attribute(attribute:"synopsis", value:
"A cross-site scripting vulnerability in SQL Server could allow an
elevation of privilege.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Microsoft SQL Server installed. This
version of SQL Server is affected by multiple vulnerabilities :

  - A cross-site scripting vulnerability exists in the
    SQL Master Data Services. (CVE-2014-1820)

  - A denial of service vulnerability exists in SQL Server.
    (CVE-2014-4061)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS14-044");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2008, 2008 R2,
2012, and 2014.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS14-044';
kbs = make_list(
  "983814",
  "2716427",
  "2716429",
  "2716433",
  "2716434",
  "2716435",
  "2716436",
  "2716439",
  "2716440",
  "2716441",
  "2716442",
  "2754849"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
  if (version !~ "^11\.0\." && version !~ "^10\.0\." && version !~ "^10\.50\." && version !~ "^12\.0\.") continue;

  sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

  sqlarch = get_kb_item("mssql/installs/" + sqlpath + "/arch");

  if (
    (sqlpath && sqlarch && 'x64' >< sqlarch) &&
    # 2014 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2014.120.2254.0", min_version:"2014.120.2000.0", bulletin:bulletin, kb:'2977315') ||
    # 2014 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2014.120.2381.0", min_version:"2014.120.2300.0", bulletin:bulletin, kb:'2977316')
  )
  {
    vuln++;
  }

  if (
    sqlpath &&

    # 2012 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.3153.0", min_version:"2011.110.3000.0", bulletin:bulletin, kb:'2977326') ||

    # 2012 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.3460.0", min_version:"2011.110.3300.0", bulletin:bulletin, kb:'2977325') ||

    # 2008 R2 SP1 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2009.100.4321.0", min_version:"2009.100.4251.0", bulletin:bulletin, kb:'2977319') ||

    # 2008 R2 SP1 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2009.100.4033.0", min_version:"2009.100.4000.0", bulletin:bulletin, kb:'2977320') ||

    # 2008 SP3 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2007.100.5869.0", min_version:"2007.100.5750.0", bulletin:bulletin, kb:"2977322") ||

    # 2008 SP3 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2007.100.5520.0", min_version:"2007.100.5500.0", bulletin:bulletin, kb:'2977321')
  )
  {
    vuln++;
  }
}
hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  set_kb_item(name:"www/0/XSS", value:TRUE);
  hotfix_security_warning();
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
