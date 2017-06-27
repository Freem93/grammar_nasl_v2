#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51351);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/05/26 16:03:22 $");

  script_name(english:"Microsoft .NET Framework Detection");
  script_summary(english:"Checks if Microsoft .NET Framework is installed.");

  script_set_attribute(attribute:"synopsis", value:
"A software framework is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Microsoft .NET Framework, a software framework for Microsoft Windows
operating systems, is installed on the remote host.");
  script_set_attribute(attribute:"see_also", value:"https://www.microsoft.com/net/");
  # https://support.microsoft.com/en-us/help/318785/how-to-determine-which-versions-and-service-pack-levels-of-the-microsoft-.net-framework-are-installed
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af642f11");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

net_fw_install_root = '';

key = "SOFTWARE\Microsoft\.NETFramework";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value =  RegQueryValue(handle:key_h, item:"InstallRoot");
  if(!isnull(value))
  {
    net_fw_install_root = value[1];
    set_kb_item(name:"SMB/net_framework/InstallRoot",value:net_fw_install_root);
  }

  RegCloseKey(handle:key_h);
}

if (!net_fw_install_root)
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0,"Microsoft .NET Framework is not installed on the remote host.");
}

# Find where it's installed.
sp =  '';
path = '';
info2  = '';
version = '';
full_version = '';
unknown_index = 0;

install_types = make_list("Full","Client","");

key = "SOFTWARE\Microsoft\NET Framework Setup\NDP";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    # \v4, v3.5
    if (strlen(subkey) && subkey =~ "^[v0-9.]+$")
    {
      # Ignore the registry entry for v4.0 as this will not contain
      # Full or Client entries when .NET 4.0 is installed and
      # with 4.5.x installed, the v4.0 entry will have Client and flag
      # so we ignore this below.  Note that 4.5 replaces the 4.0 assemblies
      # https://msdn.microsoft.com/en-us/library/5a4x27ek%28v=vs.110%29.aspx
      if (subkey =~ "^v4\.0") continue;
      foreach type (install_types)
      {
        key2 = key + "\" + subkey + '\\' + type;
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if(!isnull(key2_h))
        {
          value = RegQueryValue(handle:key2_h, item:"Install");
          if(!isnull(value) && value[1])
          {
            extra = make_array();
            version = ereg_replace(pattern:"^v([0-9.]+)$",string:subkey,replace:"\1");
            if (version =~ "^4")
            {
              # http://msdn.microsoft.com/en-us/library/hh925568(v=vs.110).aspx
              dotnet_release = RegQueryValue(handle:key2_h, item:"Release");
              if(!isnull(dotnet_release) && dotnet_release[1])
              {
                if (dotnet_release[1] == '378389')
                  version = '4.5';
                if (dotnet_release[1]=='378675' || dotnet_release[1]=='378758')
                  version = '4.5.1';
                # 380013 is from https://support.microsoft.com/en-us/kb/3099856
                if (dotnet_release[1] == '379893' || dotnet_release[1]=='379962' || dotnet_release[1]=='380013')
                  version = '4.5.2';
                if (dotnet_release[1] == '381029' || dotnet_release[1] == '393273')
                  version = '4.6 Preview';
                # 393295 is Windows 10, 393297 is all other versions.
                if (dotnet_release[1] == '393295' || dotnet_release[1] == '393297')
                  version = '4.6';
                # 394254 is Windows 10, 394271 is all other versions.
                # 394294 is from https://support.microsoft.com/en-us/kb/3146716
                if (dotnet_release[1] == '394254' || dotnet_release[1] == '394271' || dotnet_release[1] == '394294')
                  version = '4.6.1';
                # 394747 is Windows 10, 394748 is all other versions. Pre-view numbers.
                if (dotnet_release[1] == '394747' || dotnet_release[1] == '394748' ||
                # 394802 is Windows 10, 394806 is all other versions. Anniversary Update.
                    dotnet_release[1] == '394802' || dotnet_release[1] == '394806')
                  version = '4.6.2';
                if (dotnet_release[1] == '460798' || dotnet_release[1] == '460805')
                  version = '4.7';
              }
            }
            info2 += " + Version : "+ version + '\n';

            if(type)
            {
              info2  += ' - Install Type : '+ type + '\n';
              extra['Install Type'] = type;
            }

            value =  RegQueryValue(handle:key2_h, item:"Version");
            if(!isnull(value) && value[1])
            {
              full_version = value[1] ;
              info2 += ' - Full Version : '+ full_version +'\n';
              extra['Full Version'] = full_version;
            }

            # Service pack
            value =  RegQueryValue(handle:key2_h, item:"SP");
            if(!isnull(value))
            {
              sp = value[1];
              info2  += ' - SP : '+ sp +'\n';
              extra['SP'] = sp;
            }

            value =  RegQueryValue(handle:key2_h, item:"InstallPath");
            if(!isnull(value) && value[1])
            {
              path = value[1];
              info2 += ' - Path : ' + path +'\n';
            }
            else
            {
              path = "Unknown " + unknown_index++;
            }
             info2 += '\n';

            register_install(
              app_name:"Microsoft .NET Framework",
              path:path,
              version:version,
              extra:extra,
              cpe:"cpe:/a:microsoft:.net_framework");
          }
          RegCloseKey(handle:key2_h);
        }
         version = full_version = sp = path = '';
      }
    }
  }
  RegCloseKey(handle:key_h);
}

# Is there evidence of v1.0 installed??

v1_installed = 0;
key = "Software\Microsoft\.NETFramework\Policy\v1.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value =  RegQueryValue(handle:key_h, item:"3705");
  if(!isnull(value))
    v1_installed = 1;

  RegCloseKey(handle:key_h);
}

# Now get the Full version/SP

if(v1_installed)
{
  keys = make_list("Software\Microsoft\Active Setup\Installed Components\{78705f0d-e8db-4b2d-8193-982bdda15ecd}",
                 "Software\Microsoft\Active Setup\Installed Components\{FDC11A6F-17D1-48f9-9EA3-9051954BAA24}");

  foreach key (keys)
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      version =  "1.0.3705";
      info2 += " + Version : "+ version + '\n';

      value = RegQueryValue(handle:key_h, item:"Version");
      if (!isnull(value))
      {
        extra = make_array();
        v = split(value[1],sep:",",keep:FALSE);

        full_version =  join(v, sep:".");

        info2 += ' - Full Version : '+ full_version +'\n';
        extra['Full Version'] = full_version;

        # extract the SP , for e.g. 1.0.3705.1
        # 1 is the SP.
        matches = eregmatch(pattern:"^[0-9]+\.[0-9]+\.[0-9]+\.([0-9]+)$",string:full_version);
        if(!isnull(matches))
        {
          sp = matches[1];
          info2  += ' - SP : '+ sp +'\n';
          extra['SP'] = sp;
        }

        register_install(
          app_name:"Microsoft .NET Framework",
          path:"Unknown",
          version:version,
          extra:extra,
          cpe:"cpe:/a:microsoft:.net_framework");
      }
      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);
NetUseDel();

if (info2)
{
  if (report_verbosity > 0)
  {
    report = '\n'+
      'The remote host has the following version(s) of Microsoft .NET Framework\n'+
      'installed : \n\n'+
      info2;
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else exit(0, "Microsoft .NET Framework is not installed on the remote host.");
