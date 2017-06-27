#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55129);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2011-1280");
  script_bugtraq_id(48196);
  script_osvdb_id(72934);
  script_xref(name:"MSFT", value:"MS11-049");
  script_xref(name:"IAVB", value:"2011-B-0064");

  script_name(english:"MS11-049: Vulnerability in the Microsoft XML Editor Could Allow Information Disclosure (2543893)");
  script_summary(english:"Checks version of Microsoft XML editor.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote Windows host has an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"An application on the remote host has an XML external entity
vulnerability. When parsing a specially crafted Web Service Discovery
(.disco) file, external XML entities are allowed for untrusted user
input. This could result in information disclosure.

A remote attacker could exploit this by tricking a user into opening a
specially crafted .disco file, resulting in the disclosure of
sensitive information.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-049");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for InfoPath 2007 and 2010,
SQL Server 2005, 2008, and 2008 R2, SQL Server Management Studio
Express 2005, Visual Studio 2005, 2008, and 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:infopath");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS11-049';
kbs = make_list("2251481", "2251487", "2251489", "2494086", "2494089", "2494094", "2494112", "2494113", "2494120", "2494123", "2510061", "2546869");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:rootfile);

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

vuln = 0;
sql_ver_list = get_kb_list("mssql/installs/*/SQLVersion");
infopath_vers = get_kb_list("SMB/Office/InfoPath/*/ProductPath");

# Look in the registry for install info on a few of the apps being tested
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
  if (!isnull(item))
  {
    sqldts_path = item[1];
    sqldts_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:sqldts_path);
  }

  RegCloseKey(handle:key_h);
}

# SQL Server 2005 Notification Services
key = "SOFTWARE\Microsoft\Microsoft SQL Server\90\NS\Setup";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"SQLPath");
  if (!isnull(item))
  {
    sqlns_path = item[1];
    sqlns_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:sqlns_path);
  }

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
        if (!isnull(item))
        {
          sqlrs_path = item[1];
          sqlrs_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:sqlrs_path);
        }

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
        if (!isnull(item))
        {
          sqlas_path = item[1];
          sqlas_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:sqlas_path);
        }

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
  if (!isnull(item))
  {
    sql2k5_path = item[1];
    sql2k5_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:sql2k5_path);
  }

  RegCloseKey(handle:key_h);
}

# SQL Server 2008
key = "SOFTWARE\Microsoft\Microsoft SQL Server\100";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"VerSpecificRootDir");
  if (!isnull(item))
  {
    sql2k8_path = item[1];
    sql2k8_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:sql2k8_path);
  }

  RegCloseKey(handle:key_h);
}

# Detect SQL Server Management Studio Express Edition 2005
key = "SOFTWARE\Microsoft\Microsoft SQL Server\90\Tools\ShellSEM";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    ssmsee_path = item[1];
    ssmsee_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:ssmsee_path);
  }

  RegCloseKey(handle:key_h);
}

# Detect SQL Server 2005 Tools
key = "SOFTWARE\Microsoft\Microsoft SQL Server\90\Tools\Shell";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    sql2005_tools_path = item[1];
    sql2005_tools_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:sql2005_tools_path);
  }

  RegCloseKey(handle:key_h);
}

# Detect VSTA
key = "SOFTWARE\Microsoft\VSTA\8.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    vsta_path = item[1];
    vsta_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:vsta_path);
  }

  RegCloseKey(handle:key_h);
}

# Detect Visual Studio 2005 installs
key = "SOFTWARE\Microsoft\VisualStudio\8.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    vs2005_path = item[1];
    vs2005_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:vs2005_path);
  }

  RegCloseKey(handle:key_h);
}

# Detect Visual Studio 2008 installs
key = "SOFTWARE\Microsoft\VisualStudio\9.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    vs2008_path = item[1];
    vs2008_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:vs2008_path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}


# SQL Server Management Studio Express Edition
if (ssmsee_path)
{
  path = ssmsee_path + '\\Xml';

  if (hotfix_is_vulnerable(file:"Microsoft.XmlEditor.dll", version:"2.0.50727.5065", min_version:"2.0.50727.0", path:path, bulletin:bulletin, kb:'2546869'))
  {
    vuln++;
  }
}

# InfoPath
if (vsta_path && !isnull(infopath_vers))
{
  path = vsta_path + '\\Xml';

  foreach install (keys(infopath_vers))
  {
    infopath_ver = install - 'SMB/Office/InfoPath/' - '/ProductPath';
    if (
      (infopath_ver =~ '^12' && hotfix_is_vulnerable(file:"Microsoft.XmlEditor.dll", version:"2.0.50727.5065", min_version:"2.0.50727.0", path:path, bulletin:bulletin, kb:'2510061')) ||
      (infopath_ver =~ '^14' && hotfix_is_vulnerable(file:"Microsoft.XmlEditor.dll", version:"2.0.50727.5065", min_version:"2.0.50727.0", path:path, bulletin:bulletin, kb:'2510065'))
    )
    {
      vuln++;
      break; # Don't bother flagging both versions, as the same file is patched.
    }
  }
}

# Visual Studio 2005 SP1
if (vs2005_path && (!vsta_path || (vsta_path && (vs2005_path != vsta_path))))
{
  path = vs2005_path + '\\Xml';

  if (hotfix_is_vulnerable(file:"Microsoft.XmlEditor.dll", version:"2.0.50727.5065", min_version:"2.0.50727.0", path:path, bulletin:bulletin, kb:'2251481'))
  {
    vuln++;
  }
}

# Visual Studio 2008 SP1
if (vs2008_path)
{
  path = vs2008_path + '\\Xml';

  if (hotfix_is_vulnerable(file:"Microsoft.XmlEditor.dll", version:"3.5.30729.5665", min_version:"3.5.30729.0", path:path, bulletin:bulletin, kb:'2251487'))
  {
    vuln++;
  }
}

# Visual Studio 2010
vs2010_dir = "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.XmlEditor\v4.0_10.0.0.0__b03f5f7f11d50a3a"; # under the windows directory
if (hotfix_is_vulnerable(file:"Microsoft.XmlEditor.dll", version:"10.0.30319.462", min_version:"10.0.30319.0", dir:vs2010_dir, bulletin:bulletin, kb:'2251489'))
{
  vuln++;
}

# SQL Server 2008 & 2008 R2
if (
  sql2k8_path &&
  (
  # 2008 R2 QFE: BIDS, DB Services Core Instance, DB Services Core Shared, Mgmt Studio, SQL Tools
  hotfix_is_vulnerable(path:sql2k8_path + "\Tools\binn", file:"sqlsvc.dll", version:"2009.100.1790.0", min_version:"2009.100.1700.0", bulletin:bulletin, kb:'2494086') ||
  # 2008 R2 QFE: SQL Analysis Services, Database Services Common Core
  hotfix_is_vulnerable(path:sql2k8_path + "\SDK\Assemblies", file:"microsoft.analysisservices.dll", version:"10.50.1790.0", min_version:"10.50.1700.0", bulletin:bulletin, kb:'2494086') ||
  # 2008 R2 QFE: Integration Services
  hotfix_is_vulnerable(path:sql2k8_path + "\DTS\binn", file:"dts.dll", version:"2009.100.1790.0", min_version:"2009.100.1700.0", bulletin:bulletin, kb:'2494086') ||
  # 2008 R2 QFE: SQL Browser Service
  hotfix_is_vulnerable(path:sql2k8_path + "\KeyFile\1033", file:"sqlbrowser_keyfile.dll", version:"2009.100.1790.0", min_version:"2009.100.1700.0", bulletin:bulletin, kb:'2494086') ||
  # 2008 R2 QFE: SQL Writer
  hotfix_is_vulnerable(path:sql2k8_path + "\KeyFile\1033", file:"sqlwriter_keyfile.dll", version:"2009.100.1790.0", min_version:"2009.100.1700.0", bulletin:bulletin, kb:'2494086') ||

  # 2008 R2 GDR: BIDS, DB Services Core Shared, Integration services, Mgmt Studio, SQL Tools
  hotfix_is_vulnerable(path:sql2k8_path + "\DTS\PipelineComponents", file:"microsoft.sqlserver.adonetsrc.dll", version:"10.50.1617.0", min_version:"10.50.1600.0", bulletin:bulletin, kb:'2494088') ||
  # 2008 R2 GDR: Database Services Common Core
  hotfix_is_vulnerable(path:sql2k8_path + "\COM", file:"msgprox.dll", version:"2009.100.1617.0", min_version:"2009.100.1600.0", bulletin:bulletin, kb:'2494088') ||

  # 2008 SP2 QFE: BIDS, DB Services Core Instance, DB Services Core Shared, Mgmt Studio, SQL Tools
  hotfix_is_vulnerable(path:sql2k8_path + "\Tools\binn", file:"sqlsvc.dll", version:"2007.100.4311.0", min_version:"2007.100.4200.0", bulletin:bulletin, kb:'2494094') ||
  # 2008 SP2 QFE: Database Services Common Core
  hotfix_is_vulnerable(path:sql2k8_path + "\COM", file:"msgprox.dll", version:"2007.100.4311.0", min_version:"2007.100.4200.0", bulletin:bulletin, kb:'2494094') ||
  # 2008 SP2 QFE: SQL Browser Service
  hotfix_is_vulnerable(path:sql2k8_path + "\KeyFile\1033", file:"sqlbrowser_keyfile.dll", version:"2007.100.4311.0", min_version:"2007.100.4200.0", bulletin:bulletin, kb:'2494094') ||
  # 2008 SP2 QFE: Integration Services
  hotfix_is_vulnerable(path:sql2k8_path + "\DTS\binn", file:"dts.dll", version:"2007.100.4311.0", min_version:"2007.100.4200.0", bulletin:bulletin, kb:'2494094') ||

  # 2008 R2 GDR: BIDS, DB Services Core Shared, Integration services, Mgmt Studio, SQL Tools
  hotfix_is_vulnerable(path:sql2k8_path + "\DTS\Binn", file:"dtspipeline.dll", version:"2007.100.4064.0", min_version:"2007.100.4000.0", bulletin:bulletin, kb:'2494089') ||
  # 2008 R2 GDR: Database Services Common Core
  hotfix_is_vulnerable(path:sql2k8_path + "\COM", file:"msgprox.dll", version:"2007.100.4064.0", min_version:"2007.100.4000.0", bulletin:bulletin, kb:'2494089') ||

  # 2008 SP1 QFE: BIDS, DB Services Core Instance, DB Services Core Shared, Mgmt Studio, SQL Tools
  hotfix_is_vulnerable(path:sql2k8_path + "\Tools\binn", file:"sqlsvc.dll", version:"2007.100.2841.0", min_version:"2007.100.2700.0", bulletin:bulletin, kb:'2494100') ||
  # 2008 SP1 QFE: Database Services Common Core
  hotfix_is_vulnerable(path:sql2k8_path + "\COM", file:"msgprox.dll", version:"2007.100.2841.0", min_version:"2007.100.2700.0", bulletin:bulletin, kb:'2494100') ||
  # 2008 SP1 QFE: SQL Browser Service
  hotfix_is_vulnerable(path:sql2k8_path + "\KeyFile\1033", file:"sqlbrowser_keyfile.dll", version:"2007.100.2841.0", min_version:"2007.100.2700.0", bulletin:bulletin, kb:'2494100') ||
  # 2008 SP1 QFE: Integration Services
  hotfix_is_vulnerable(path:sql2k8_path + "\DTS\binn", file:"dts.dll", version:"2007.100.2841.0", min_version:"2007.100.2700.0", bulletin:bulletin, kb:'2494100') ||

  # 2008 SP1 GDR: Management Studio
  hotfix_is_vulnerable(path:sql2k8_path + "\KeyFile\1033", file:"Sql_ssms_keyfile.dll", version:"2007.100.2573.0", min_version:"2007.100.2000.0", bulletin:bulletin, kb:'2494096')

  )
)
{
  vuln++;
}


# SQL Server 2005
if (
  sql2k5_path &&
  (
  # 2005 SP4 QFE: Data Transformation Services, Database Engine, SQL Tools
  hotfix_is_vulnerable(path:sql2k5_path + "\DTS\binn", file:"dts.dll", version:"2005.90.5292.0", min_version:"2005.90.5200.0", bulletin:bulletin, kb:'2494123') ||
  # 2005 SP4 QFE: Notification Services
  hotfix_is_vulnerable(path:sql2k5_path + "\Shared", file:"isacctchange.dll", version:"2005.90.5292.0", min_version:"2005.90.5200.0", bulletin:bulletin, kb:'2494123') ||

  # 2005 SP4 GDR: Data Transformation Services
  hotfix_is_vulnerable(path:sql2k5_path + "\DTS\binn", file:"msdtssrvr.exe", version:"9.0.5057.0", min_version:"9.0.5000.0", bulletin:bulletin, kb:'2494120') ||

  # 2005 SP3 GDR: Data Transformation Services
  hotfix_is_vulnerable(path:sql2k5_path + "\DTS\binn", file:"msdtssrvr.exe", version:"9.0.4060.0", min_version:"9.0.4000.0", bulletin:bulletin, kb:'2494113')
  )
)
{
  vuln++;
}

# SQL Server 2005 Notification Services
if (
  sqlns_path &&
  (
  # 2005 SP4 GDR: Notification Services
  hotfix_is_vulnerable(path:sqlns_path + "\bin", file:"nsservice.exe", version:"9.0.5057.0", min_version:"9.0.5000.0", bulletin:bulletin, kb:'2494120') ||

  # 2005 SP3 QFE: Notification Services
  hotfix_is_vulnerable(path:sqlns_path + "\bin", file:"nsservice.exe", version:"9.0.4340.0", min_version:"9.0.4200.0", bulletin:bulletin, kb:'2494112') ||

  # 2005 SP3 GDR: Notification Services
  hotfix_is_vulnerable(path:sqlns_path + "\bin", file:"nsservice.exe", version:"9.0.4060.0", min_version:"9.0.4000.0", bulletin:bulletin, kb:'2494113')
  )
)
{
  vuln++;
}

foreach item (keys(sql_ver_list))
{
  item -= 'mssql/installs/';
  item -= '/SQLVersion';
  sqlpath = item;

  share = hotfix_path2share(path:sqlpath);
  if (!is_accessible_share(share:share)) continue;

  sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition_type");
  if (isnull(sqltype)) sqltype = get_kb_item("mssql/installs/" + sqlpath + "/edition");

  # Database Services Core Instance
  if (
    sqlpath &&
    "Windows Internal Database" >!< sqltype &&
    (
    # 2008 R2 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2007.100.4064.0", min_version:"2007.100.4000.0", bulletin:bulletin, kb:'2494089') ||
    # 2008 SP1 GDR
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2007.100.2573.0", min_version:"2007.100.2000.0", bulletin:bulletin, kb:'2494096') ||
    # 2005 SP4 GDR (Database Engine)
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2005.90.5057.0", min_version:"2005.90.5000.0", bulletin:bulletin, kb:'2494120') ||
    # 2005 SP3 GDR (Database Engine + SQL Tools)
    hotfix_is_vulnerable(path:sqlpath, file:"sqlservr.exe", version:"2005.90.4060.0", min_version:"2005.90.4000.0", bulletin:bulletin, kb:'2494113')
    )
  )
  {
    vuln++;
  }
}

# SQL Server System CLR Types
if (
  # 2008 SP2 QFE
  hotfix_is_vulnerable(dir:"\system32", file:"sqlserverspatial.dll", version:"2007.100.4311.0", min_version:"2007.100.4200.0", bulletin:bulletin, kb:'2494094') ||
  # 2008 SP1 QFE
  hotfix_is_vulnerable(dir:"\system32", file:"sqlserverspatial.dll", version:"2007.100.2841.0", min_version:"2007.100.2700.0", bulletin:bulletin, kb:'2494100')
)
{
  vuln++;
}

# SQL Native Client
if (
  # SQL Server 2008 R2 QFE
  hotfix_is_vulnerable(dir:"\system32", file:"Sqlncli10.dll", version:"2009.100.1790.0", min_version:"2009.100.1700.0", bulletin:bulletin, kb:'2494086') ||
  # SQL Server 2008 R2 GDR
  hotfix_is_vulnerable(dir:"\system32", file:"Sqlncli10.dll", version:"2009.100.1617.0", min_version:"2009.100.1600.0", bulletin:bulletin, kb:'2494088') ||
  # SQL Server 2008 SP2 QFE
  hotfix_is_vulnerable(dir:"\system32", file:"Sqlncli10.dll", version:"2007.100.4311.0", min_version:"2007.100.4200.0", bulletin:bulletin, kb:'2494094') ||
  # SQL Server 2008 SP2 GDR
  hotfix_is_vulnerable(dir:"\system32", file:"Sqlncli10.dll", version:"2007.100.4064.0", min_version:"2007.100.4000.0", bulletin:bulletin, kb:'2494089') ||
  # SQL Server 2008 SP1 QFE
  hotfix_is_vulnerable(dir:"\system32", file:"Sqlncli10.dll", version:"2007.100.2841.0", min_version:"2007.100.2800.0", bulletin:bulletin, kb:'2494100') ||
  # SQL Server 2005 SP4 QFE
  hotfix_is_vulnerable(dir:"\system32", file:"Sqlncli.dll", version:"2005.90.5292.0", min_version:"2005.90.5200.0", bulletin:bulletin, kb:'2494123') ||
  # SQL Server 2005 SP4 GDR
  hotfix_is_vulnerable(dir:"\system32", file:"Sqlncli.dll", version:"2005.90.5000.0", min_version:"2005.90.4800.0", bulletin:bulletin, kb:'2494120') ||
  # SQL Server 2005 SP3 QFE
  hotfix_is_vulnerable(dir:"\system32", file:"Sqlncli.dll", version:"2005.90.4340.0", min_version:"2005.90.4200.0", bulletin:bulletin, kb:'2494112') ||
  # SQL Server 2005 SP3 GDR
  hotfix_is_vulnerable(dir:"\system32", file:"Sqlncli.dll", version:"2005.90.4035.0", min_version:"2005.90.4000.0", bulletin:bulletin, kb:'2494113')
)
{
  vuln++;
}

if (sql2005_tools_path)
{
  if(
  # SQL Server 2005 Tools
  hotfix_is_vulnerable(path:sql2005_tools_path, file:"microsoft.reportingservices.diagnostics.dll", version:"9.0.5292.0", min_version:"9.0.5200.0", bulletin:bulletin, kb:'2494123') ||
  hotfix_is_vulnerable(path:sql2005_tools_path, file:"microsoft.reportingservices.diagnostics.dll", version:"9.0.5057.0", min_version:"9.0.5000.0", bulletin:bulletin, kb:'2494120') ||
  hotfix_is_vulnerable(path:sql2005_tools_path, file:"microsoft.reportingservices.diagnostics.dll", version:"9.0.4340.0", min_version:"9.0.4200.0", bulletin:bulletin, kb:'2494112') ||
  hotfix_is_vulnerable(path:sql2005_tools_path, file:"microsoft.reportingservices.diagnostics.dll", version:"9.0.4060.0", min_version:"9.0.4000.0", bulletin:bulletin, kb:'2494113'))
  {
    vuln++;
  }
}

# SQL Reporting services
if (sqlrs_path)
{
  sqlrs_path += "\ReportServer\bin";

  if (
    # SQL Server 2008
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"2009.100.1790.0", min_version:"2009.100.1700.0", bulletin:bulletin, kb:'2494086') ||
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"2009.100.1617.0", min_version:"2009.100.1600.0", bulletin:bulletin, kb:'2494088') ||
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"2007.100.4311.0", min_version:"2007.100.4200.0", bulletin:bulletin, kb:'2494094') ||
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"2007.100.4064.0", min_version:"2007.100.4000.0", bulletin:bulletin, kb:'2494089') ||
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"2007.100.2841.0", min_version:"2007.100.2000.0", bulletin:bulletin, kb:'2494100') ||

    # SQL Server 2005
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"9.0.5292.0", min_version:"9.0.5200.0", bulletin:bulletin, kb:'2494123') ||
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"9.0.5057.0", min_version:"9.0.5000.0", bulletin:bulletin, kb:'2494120') ||
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"9.0.4340.0", min_version:"9.0.4200.0", bulletin:bulletin, kb:'2494112') ||
    hotfix_is_vulnerable(path:sqlrs_path, file:"reportingservicesservice.exe", version:"9.0.4060.0", min_version:"9.0.0.0", bulletin:bulletin, kb:'2494113')
  )
  {
    vuln++;
  }
}

# SQL
if (sqlas_path)
{
  sqlas_path += "\bin";

  if (
    # SQL Server 2008
    hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"10.50.1790.0", min_version:"10.50.1700.0", bulletin:bulletin, kb:'2494086') ||
    hotfix_is_vulnerable(path:sqlas_path, file:"xmsrv.dll", version:"10.50.1617.0", min_version:"10.50.0.0", bulletin:bulletin, kb:'2494088') ||
    hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"10.0.4311.0", min_version:"10.0.4000.0", bulletin:bulletin, kb:'2494094') ||
    hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"10.0.2841.0", min_version:"10.0.2500.0", bulletin:bulletin, kb:'2494100') ||

    # SQL Server 2005
    hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"9.0.5292.0", min_version:"9.0.5200.0", bulletin:bulletin, kb:'2494123') ||
    hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"9.0.5057.0", min_version:"9.0.5000.0", bulletin:bulletin, kb:'2494120') ||
    hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"9.0.4340.0", min_version:"9.0.4200.0", bulletin:bulletin, kb:'2494112') ||
    hotfix_is_vulnerable(path:sqlas_path, file:"msmdsrv.exe", version:"9.0.4060.0", min_version:"9.0.4000.0", bulletin:bulletin, kb:'2494113')
  )
  {
    vuln++;
  }
}

hotfix_check_fversion_end();

if (vuln)
{
  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  hotfix_security_warning();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
