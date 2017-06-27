#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42117);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2009-0090", "CVE-2009-0091", "CVE-2009-2497");
  script_bugtraq_id(36611, 36617, 36618);
  script_osvdb_id(58849, 58850, 58851);
  script_xref(name:"MSFT", value:"MS09-061");

  script_name(english:string( "MS09-061: Vulnerabilities in the Microsoft .NET Common Language Runtime Could Allow Remote Code Execution (974378)" ) );
  script_summary(english:"Checks version of mscorlib.dll");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft .NET Common Language Runtime is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of the Microsoft .NET
Framework that is affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the
    Microsoft .NET Framework that could allow a malicious
    Microsoft .NET application to obtain a managed pointer
    to stack memory that is no longer used. The malicious
    Microsoft .NET application could then use this pointer
    to modify legitimate values placed at that stack
    location
    later, leading to arbitrary, unmanaged code execution.
    Microsoft .NET applications that are not malicious are
    not at risk for being compromised because of this
    vulnerability.(CVE-2009-0090)

  - A remote code execution vulnerability exists in the
    Microsoft
    .NET Framework that could allow a malicious Microsoft
    .NET
    application to bypass a type equality check. The
    malicious
    Microsoft .NET could exploit this vulnerability by
    casting
    an object of one type into another type, leading to
    arbitrary,
    unmanaged code execution.  Microsoft .NET applications
    that
    are not malicious are not at risk for being compromised
    because
    of this vulnerability.(CVE-2009-0091)

  - A remote code execution vulnerability exists in the
    Microsoft
    .NET Framework that can allow a malicious Microsoft .NET
    application or a malicious Silverlight application to
    modify
    memory of the attacker's choice, leading to arbitrary,
    unmanaged
    code execution. Microsoft .NET applications and
    Silverlight
    applications that are not malicious are not at risk for
    being
    compromised because of this
    vulnerability.(CVE-2009-2497)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-061");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for .NET Framework 1.1, 2.0
and 3.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:silverlight");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "silverlight_detect.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS09-061';
kbs = make_list("953297", "953300", "970363", "974291", "974292", "974417", "9744677", "974468", "974469", "974470");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

rootfile = hotfix_get_systemroot();
if(!rootfile)
  exit(1, "Can't get system root." );



share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:rootfile);
dotNET11 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v1.1.4322\mscorlib.dll", string:rootfile);
dotNET20 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Microsoft.Net\Framework\v2.0.50727\mscorlib.dll", string:rootfile);

login	  =  kb_smb_login();
pass  	=  kb_smb_password();
domain 	=  kb_smb_domain();
port    =  kb_smb_transport();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (r != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

osver = NULL;
ossp = NULL;

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}
key = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:'ProductName');
  if (!isnull(item)) osver = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);
if (isnull(osver))
{
  NetUseDel();
  exit(1, 'Couldn\'t determine the version of Windows running on the remote host.');
}
ossp = get_kb_item_or_exit('SMB/CSDVersion');

r = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if ( r != 1 ) audit(AUDIT_SHARE_FAIL, share);

report = '';
handle = CreateFile(  file:dotNET11,
                      desired_access:GENERIC_READ,
                      file_attributes:FILE_ATTRIBUTE_NORMAL,
                      share_mode:FILE_SHARE_READ,
                      create_disposition:OPEN_EXISTING );
if( ! isnull(handle) )
{
  v = GetFileVersion(handle:handle);
  CloseFile(handle:handle);
  if ( !isnull( v ) )
  {
    if ( v[0] == 1 && v[1] == 1 && v[2] == 4322 && v[3] < 2443 )
    {
      report = string(
      '  Product           : Microsoft .NET Framework 1.1\n',
      '  Path              : ', dotNET11, '\n',
      '  Installed version : 1.1.4322.', v[3], '\n',
      '  Fix               : 1.1.4322.2443\n' );
      hotfix_add_report(report, bulletin:bulletin, kb:'953297');
    }
  }
}

handle = CreateFile(  file:dotNET20,
                      desired_access:GENERIC_READ,
                      file_attributes:FILE_ATTRIBUTE_NORMAL,
                      share_mode:FILE_SHARE_READ,
                      create_disposition:OPEN_EXISTING );
vuln = FALSE;
if( ! isnull(handle) )
{
  v = GetFileVersion(handle:handle);
  CloseFile(handle:handle);
  if ( !isnull( v ) )
  {
    if ( v[0] == 2 && v[1] == 0 && v[2] == 50727 )
    {
      if ( report ) report = string( report, '\n' );

      if (
        hotfix_check_sp(vista:1) > 0 &&
        v[3] > 0 && v[3] < 1003
      )
      {
        # .NET 2.0 SP0 is only affected on Vista SP0
        report = string(
          '  Product           : Microsoft .NET Framework 2.0\n',
          '  Path              : ', dotNET20, '\n',
          '  Installed version : 2.0.50727.', v[3], '\n',
          '  Fix               : 2.0.50727.1003\n' );
        hotfix_add_report(report, bulletin:bulletin, kb:'974468');
        vuln = TRUE;
      }
      else if (
        hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:2) > 0 &&
        v[3] > 1500 && v[3] < 1873
      )
      {
        # .NET 2.0 SP1 affected on all win2k, xp, 2k3, and vista/2k8 before SP2
        report = string(
          '  Product           : Microsoft .NET Framework 2.0 SP1\n',
          '  Path              : ', dotNET20, '\n',
          '  Installed version : 2.0.50727.', v[3], '\n',
          '  Fix               : 2.0.50727.1873\n'  );
        if (hotfix_check_sp(win2k:6, xp:4, win2003:3) > 0) hotfix_add_report(report, bulletin:bulletin, kb:'953300');
        else if ('Windows Vista' >< osver)
        {
          if (ossp = 'Service Pack 0') hotfix_add_report(report, bulletin:bulletin, kb:'974292');
          else if (ossp == 'Service Pack 1') hotfix_add_report(report, bulletin:bulletin, kb:'974291');
        }
        else if ('Windows Server' >< osver && '2008' >< osver && 'R2' >!< osver)
          hotfix_add_report(report, bulletin:bulletin, kb:'974291');
        vuln = TRUE;
      }
      else if ( v[3] > 3000 && v[3] < 3603  )
      {
        report = string(
          '  Product           : Microsoft .NET Framework 2.0 SP2\n',   # XP to Vista SP1
          '  Path              : ', dotNET20, '\n',
          '  Installed version : 2.0.50727.', v[3], '\n',
          '  Fix               : 2.0.50727.3603\n'  );
        if (hotfix_check_sp(win2k:6, xp:4, win2003:3) > 0) hotfix_add_report(report, bulletin:bulletin, kb:'974417');

        else if ('Windows Vista' >< osver)
        {
          if (ossp == 'Service Pack 0') hotfix_add_report(report, bulletin:bulletin, kb:'9744677');
          else if (ossp == 'Service Pack 1') hotfix_add_report(report, bulletin:bulletin, kb:'974469');
        }
        vuln = TRUE;
      }
      else if ( v[3] > 4000 && v[3] < 4200  )
      {
        report = string(
          '  Product           : Microsoft .NET Framework 2.0 SP2\n',   # Vista SP2
          '  Path              : ', dotNET20, '\n',
          '  Installed version : 2.0.50727.', v[3], '\n',
          '  Fix               : 2.0.50727.4200\n'  );
        if ('Windows Vista' >< osver) hotfix_add_report(report, bulletin:bulletin, kb:'974469');
        else if ('Windows Server' >< osver && '2008' >< osver && 'R2' >!< osver)
        {
          if (ossp == 'Service Pack 0' || ossp == 'Service Pack 1') hotfix_add_report(report, bulletin:bulletin, kb:'974469');
          else hotfix_add_report(report, bulletin:bulletin, kb:'974470');
        }
        vuln = TRUE;
      }
      else if (
        hotfix_check_sp(win7:1) > 0 &&
        v[3] > 4800 && v[3] < 4927
      )
      {
        # .NET 3.5.1 only affected on win7 and 2k8 r2
        report = string(
          '  Product           : Microsoft .NET Framework 3.5.1\n',
          '  Path              : ', dotNET20, '\n',
          '  Installed version : 2.0.50727.', v[3], '\n',
          '  Fix               : 2.0.50727.4927\n'  );
        hotfix_add_report(report, bulletin:bulletin, kb:'974469');
        vuln = TRUE;
      }
    }
  }
}

NetUseDel();

ver = get_kb_item( "SMB/Silverlight/Version" );
if ( !isnull( ver ) )
{
  v = split( ver, sep:'.', keep:FALSE );
  if ( int( v[0] ) < 3  )
  {
    if ( report ) report = string( report, '\n' );
    path = get_kb_item( "SMB/Silverlight/Path" );
    report = string(
    '  Product           : Microsoft Silverlight\n',
    '  Path              : ', path, '\n',
    '  Installed version : ', ver, '\n',
    '  Fix               : 3.0.40818.0\n' );
    hotfix_add_report(report, bulletin:bulletin, kb:'970363');
    vuln = TRUE;
  }
}

if (vuln)
{
  set_kb_item(name:"SMB/Missing/MS09-061", value:TRUE);
  hotfix_security_hole();
}
else
  exit( 0, 'The host is not affected.' );
