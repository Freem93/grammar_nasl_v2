#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62465);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2012-2552");
  script_bugtraq_id(55783);
  script_osvdb_id(86057);
  script_xref(name:"MSFT", value:"MS12-070");
  script_xref(name:"IAVA", value:"2012-A-0160");

  script_name(english:"MS12-070: Vulnerability in SQL Server Could Allow Elevation of Privilege (2754849)");
  script_summary(english:"Determines the version of SQL Server");

  script_set_attribute(attribute:"synopsis", value:
"A cross-site scripting vulnerability in SQL Server could allow
elevation of privilege.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Microsoft SQL Server installed. This
version of SQL Server is running SQL Server Reporting Services (SRSS),
that is affected by a cross-site scripting (XSS) vulnerability that
could allow elevation of privileges. Successful exploitation could
allow an attacker to execute arbitrary commands on the SSRS site in
the context of the targeted user. An attacker would need to entice a
user to visit a specially crafted link in order to exploit the
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-070");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2000, 2005,
2008, 2008 R2, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS12-070';
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

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

ver_list = get_kb_list("mssql/installs/*/SQLVersion");

if (isnull(ver_list))
   audit(AUDIT_NOT_INST, "Microsoft SQL Server");

vuln = 0;

# Look in the registry for install info
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# SQL Server 2005 Data Transformation Services
key = "SOFTWARE\Microsoft\Microsoft SQL Server\90\DTS\Setup";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"SQLPath");
  if (!isnull(item)) sqldts_path = item[1];

  RegCloseKey(handle:key_h);
}

# SQL Server 2005 Notification Services
key = "SOFTWARE\Microsoft\Microsoft SQL Server\90\NS\Setup";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"SQLPath");
  if (!isnull(item)) sqlns_path = item[1];

  RegCloseKey(handle:key_h);
}

# SQL Server Reporting Services
key = "SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\RS";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegEnumValue(handle:key_h, index:0);
  if (!isnull(item))
  {
    item = RegQueryValue(handle:key_h, item:item[1]);
    if (item)
    {
      inst = item[1];

      key2 = "SOFTWARE\Microsoft\Microsoft SQL Server\" + inst + "\Setup";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"SQLPath");
        if (!isnull(item)) sqlrs_path = item[1];

        RegCloseKey(handle:key2_h);
      }
    }
  }

  RegCloseKey(handle:key_h);
}

# SQL Server Analysis Services
key = "SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\OLAP";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegEnumValue(handle:key_h, index:0);
  if (!isnull(item))
  {
    item = RegQueryValue(handle:key_h, item:item[1]);
    if (item)
    {
      inst = item[1];

      key2 = "SOFTWARE\Microsoft\Microsoft SQL Server\" + inst + "\Setup";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"SQLPath");
        if (!isnull(item)) sqlas_path = item[1];

        RegCloseKey(handle:key2_h);
      }
    }
  }

  RegCloseKey(handle:key_h);
}

# SQL Server 2005
key = "SOFTWARE\Microsoft\Microsoft SQL Server\90";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"VerSpecificRootDir");
  if (!isnull(item)) sql2k5_path = item[1];

  RegCloseKey(handle:key_h);
}

# SQL Server 2008
key = "SOFTWARE\Microsoft\Microsoft SQL Server\100";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"VerSpecificRootDir");
  if (!isnull(item)) sql2k8_path = item[1];

  RegCloseKey(handle:key_h);
}

# SQL Server 2012
key = "SOFTWARE\Microsoft\Microsoft SQL Server\110";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"VerSpecificRootDir");
  if (!isnull(item)) sql2k12_path = item[1];

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

# SQL Server 2012
if (
  sqlrs_path && sql2k12_path &&
  (
  # 2012 GDR
  hotfix_is_vulnerable(path:sql2k12_path + "\DTS\PipelineComponents", file:"microsoft.sqlserver.adonetsrc.dll", version:"11.0.2218.0", min_version:"11.0.2100.0", bulletin:bulletin, kb:'2716442') ||
  # 2012 QFE
  hotfix_is_vulnerable(path:sql2k12_path + "\DTS\PipelineComponents", file:"microsoft.sqlserver.adonetsrc.dll", version:"11.0.2376.0", min_version:"11.0.2300.0", bulletin:bulletin, kb:'2716441')
  )
)
{
  vuln++;
}


# SQL Server 2008 & 2008 R2
if (
  sqlrs_path && sql2k8_path &&
  (
  # 2008 R2 QFE
  hotfix_is_vulnerable(path:sql2k8_path + "\Tools\binn", file:"sqlsvc.dll", version:"2009.100.2861.0", min_version:"2009.100.2750.0", bulletin:bulletin, kb:'2716439') ||

  # 2008 R2 QFE: SQL Analysis Services
  hotfix_is_vulnerable(path:sql2k8_path + "\SDK\Assemblies", file:"microsoft.analysisservices.dll", version:"10.50.2861.0", min_version:"10.50.2750.0", bulletin:bulletin, kb:'2716439') ||

  # 2008 R2 QFE: Integration Services
  hotfix_is_vulnerable(path:sql2k8_path + "\DTS\binn", file:"dts.dll", version:'2009.100.2861.0', min_version:"2009.100.2750.0", bulletin:bulletin, kb:'2716439'
) ||

  # 2008 R2 QFE: SQL Browser Service
  hotfix_is_vulnerable(path:sql2k8_path + "\KeyFile\1033", file:"sqlbrowser_keyfile.dll", version:"2009.100.2861.0", min_version:"2009.100.2750.0", bulletin:bulletin, kb:'2716439') ||

  # 2008 R2 QFE: SQL Writer
  hotfix_is_vulnerable(path:sql2k8_path + "\KeyFile\1033", file:"sqlwriter_keyfile.dll", version:"2009.100.2861.0", min_version:"2009.100.2750.0", bulletin:bulletin, kb:'2716439') ||

  # 2008 R2 GDR
  hotfix_is_vulnerable(path:sql2k8_path + "\DTS\PipelineComponents", file:"microsoft.sqlserver.adonetsrc.dll", version:"10.50.2861.0", min_version:"10.50.2750.0", bulletin:bulletin, kb:'2716439') ||

  # 2008 R2 GDR: Database Services Common Core
  hotfix_is_vulnerable(path:sql2k8_path + "\COM", file:"msgprox.dll", version:"2009.100.2861.0", min_version:"2009.100.2750.0", bulletin:bulletin, kb:'2716439') ||

  # 2008 SP3 QFE
  hotfix_is_vulnerable(path:sql2k8_path + "\Tools\binn", file:"xmlrw.dll", version:"2.0.3609.0", min_version:"2.0.3000.0", bulletin:bulletin, kb:'2716435')
  )
)
{
  vuln++;
}

# SQL Server Analysis Services
if (sqlas_path && sqlrs_path)
{
  sqlas_path += "\bin";

  if (
    # SQL Server 2012 GDR
    hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"11.0.2218.0", min_version:"11.0.2100.0", bulletin:bulletin, kb:'2716442') ||

    # SQL Server 2012 QFE
    hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"11.0.2376.0", min_version:"11.0.2300.0", bulletin:bulletin, kb:'2716441') ||

    # SQL Server 2008 R2 SP1 QFE
    hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"10.50.2861.0", min_version:"10.50.2750.0", bulletin:bulletin, kb:'2716439')
  )
  {
    vuln++;
  }

  foreach item (keys(ver_list))
  {
    item -= 'mssql/installs/';
    item -= '/SQLVersion';
    sqlpath = item;

    version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");
    if (version !~ "^9\.00\.") continue;

    sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
    if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

    # For SQL Server 2005 we have to make sure we don't flag Express
    # unless advanced services is installed
    if ( !isnull(sqltype) && (('Express Edition' >!< sqltype) || ('Express Edition with Advanced Services' >< sqltype)))
    {
      if (
        # SQL Server 2005 SP4 QFE
        hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"9.0.5324.0", min_version:"9.0.5200.0", bulletin:bulletin, kb:'2716427') ||

        # SQL Server 2005 SP4 GDR
        hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"9.0.5069.0", min_version:"9.0.5000.0", bulletin:bulletin, kb:'2716429')
      )
      {
        vuln++;
        break;
      }
    }
  }
}

foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");
  if (version !~ "^9\.00\.") continue;

  sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

  # SQL Server 2005 Data Transformation Services
  if (sqlrs_path && sql2k5_path && (!isnull(sqltype)) && (('Express Edition' >!< sqltype) || ('Express Edition with Advanced Services' >< sqltype)))
  {
    if (
      # 2005 SP4 QFE: Data Transformation Services
      hotfix_is_vulnerable(path:sql2k5_path + "\DTS\binn", file:"msdtssrvr.exe", version:"9.0.5324.0", min_version:"9.0.5200.0", bulletin:bulletin, kb:'2716427') ||

      # 2005 SP4 GDR: Data Transformation Services
      hotfix_is_vulnerable(path:sql2k5_path + "\DTS\binn", file:"msdtssrvr.exe", version:"9.0.5069.0", min_version:"9.0.5000.0", bulletin:bulletin, kb:'2716429')
    )
    {
      vuln++;
      break;
    }
  }
}

foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");
  if (version !~ "^9\.00\.") continue;

  sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

  # SQL Server 2005 Notification Services
  if (sqlrs_path && sqlns_path && (!isnull(sqltype)) && (('Express Edition' >!< sqltype) || ('Express Edition with Advanced Services' >< sqltype)))
  {
    if (
    # 2005 SP4 GDR: Notification Services
    hotfix_is_vulnerable(path:sqlns_path + "\bin", file:"nsservice.exe", version:"9.0.5069.0", min_version:"9.0.5000.0", bulletin:bulletin, kb:'2716429') ||

    # 2005 SP4 QFE: Notification Services
    hotfix_is_vulnerable(path:sqlns_path + "\bin", file:"nsservice.exe", version:"9.0.5324.0", min_version:"9.0.5200.0", bulletin:bulletin, kb:'2716429')
    )
    {
      vuln++;
      break;
    }
  }
}

# SQL Reporting services
if (sqlrs_path)
{
  sqlrs_path += "\ReportServer\bin";

  if (
    # SQL Server 2012 GDR
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"2011.110.2218.0", min_version:"2011.110.2100.0", bulletin:bulletin, kb:'2716442') ||

    # SQL Server 2012 QFE
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"2011.110.2376.0", min_version:"2011.110.2300.0", bulletin:bulletin, kb:'2716441') ||

    # SQL Server 2008 R2 SP1 GDR
    hotfix_is_vulnerable(path:sqlrs_path, file:"Microsoft.reportingservices.diagnostics.dll", version:"10.50.2550.0", min_version:"10.50.2500.0", bulletin:bulletin, kb:'2716440') ||

    # SQL Server 2008 R2 SP1 QFE
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"2009.100.2861.0", min_version:"2009.100.2750.0", bulletin:bulletin, kb:'2716439') ||

    # SQL Server 2008 SP2 GDR
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"2007.100.4067.0", min_version:"2007.100.4000.0", bulletin:bulletin, kb:'2716434') ||

    # SQL Server 2008 SP3 GDR
    hotfix_is_vulnerable(path:sqlrs_path, file:"Microsoft.reportingservices.diagnostics.dll", version:"10.0.5512.0", min_version:"10.0.5500.0", bulletin:bulletin, kb:'2716436') ||

    # SQL Server 2005 SP4 QFE
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"9.0.5324.0", min_version:"9.0.5200.0", bulletin:bulletin, kb:'2716427') ||
    # SQL Server 2005 SP4 GDR
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"9.0.5069.0", min_version:"9.0.5000.0", bulletin:bulletin, kb:'2716429')
  )
  {
    vuln++;
  }
  foreach item (keys(ver_list))
  {
    item -= 'mssql/installs/';
    item -= '/SQLVersion';
    sqlpath = item;

    version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");
    if (version !~ "^9\.00\.") continue;

    sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
    if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

    if (!isnull(sqltype) && ('Express Edition' >!< sqltype || 'Express Edition with Advanced Services' >< sqltype))
    {
      if (
        # SQL Server 2005 SP4 QFE
        hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"9.0.5324.0", min_version:"9.0.5200.0", bulletin:bulletin, kb:'2716427') ||
        # SQL Server 2005 SP4 GDR
        hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"9.0.5069.0", min_version:"9.0.5000.0", bulletin:bulletin, kb:'2716429')
      )
      {
        vuln++;
        break;
      }
    }
  }
}

# SQL Server 2000
foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");
  if (version !~ "^8\.00\.") continue;

  sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

  sql2000rs_path = ereg_replace(
    pattern:"^(.*)\\Binn\\?",
    replace:"\1\Reporting Services\ReportServer\bin",
    string:sqlpath,
    icase:TRUE
  );

  if (hotfix_is_vulnerable(path:sql2000rs_path, file:"reportingservicesservice.exe", version:"8.0.1077.0", min_version:"8.0.1038.0", bulletin:bulletin, kb:'983814'))
  {
    vuln++;
  }
}


# Database Services Core Instance
foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");
  if (version !~ "^11\.0\." && version !~ "^10\.0\." && version !~ "^10\.50\.") continue;

  sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

  if (
    sqlrs_path && sqlpath &&
    (
    # 2012 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.2218.0", min_version:"2011.110.2100.0", bulletin:bulletin, kb:'2716442') ||

    # 2012 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2011.110.2376.0", min_version:"2011.110.2300.0", bulletin:bulletin, kb:'2716441') ||

    # 2008 R2 SP1 QFE
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2009.100.2861.0", min_version:"2009.100.2750.0", bulletin:bulletin, kb:'2716439') ||

    # 2008 R2 SP1 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2009.100.2550.0", min_version:"2009.100.2500.0", bulletin:bulletin, kb:'2716440') ||

    # 2008 SP3 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2007.100.5512.0", min_version:"2007.100.5500.0", bulletin:bulletin, kb:'2716436') ||

    # 2008 SP2 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2007.100.4067.0", min_version:"2007.100.4000.0", bulletin:bulletin, kb:'2716434')
    )
  )
  {
    vuln++;
  }
}

foreach item (keys(ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  version = get_kb_item("mssql/installs/" + sqlpath + "/SQLVersion");
  if (version !~ "^9\.00\.") continue;

  sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

  if (sqlrs_path && sqlpath && (!isnull(sqltype) && ('Express Edition' >!< sqltype || 'Express Edition with Advanced Services' >< sqltype)))
  {
    if (
      # 2005 SP4 GDR
      hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2005.90.5069.0", min_version:"2005.90.5000.0", bulletin:bulletin, kb:'2716429') ||

      # 2005 SP4 QFE
      hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2005.90.5324.0", min_version:"2005.90.5200.0", bulletin:bulletin, kb:'2716427')
    )
    {
      vuln++;
    }
  }
}

# SQL Server System CLR Types
if (
  sqlrs_path &&
  # 2008 SP1 QFE
  hotfix_is_vulnerable(dir:"\system32", file:"sqlserverspatial.dll", version:"2009.100.2861.0", min_version:"2009.100.2750.0", bulletin:bulletin, kb:'2716439')
)
  vuln++;

hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  set_kb_item(name:"www/0/XSS", value:TRUE);
  hotfix_security_warning();
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
