#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16192);
 script_version("$Revision: 1.1813 $");
 script_cvs_date("$Date: 2016/11/22 20:39:11 $");

 script_name(english:"Trend Micro Antivirus Detection and Status");
 script_summary(english:"Checks that the remote host has Trend Micro Antivirus installed, and then makes sure the latest Vdefs are loaded.");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
 script_set_attribute(attribute:"description", value:
"Trend Micro Antivirus, a commercial antivirus software package for
Windows, is installed on the remote host. However, there is a problem
with the installation; either its services are not running or its
engine and/or virus definitions are out of date.");
 script_set_attribute(attribute:"see_also", value:"http://www.trendmicro.com/");
 script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/18");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:trend_micro_antivirus");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

 script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
 script_require_keys("SMB/name","SMB/login","SMB/password","SMB/registry_full_access","SMB/transport","SMB/Services/Enumerated");
 script_require_ports(139, 445);

 exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("datetime.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

name   =  kb_smb_name();
login  = kb_smb_login();
pass   = kb_smb_password();
port   = kb_smb_transport();
domain = kb_smb_domain();



hcf_init = 1;
if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
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

# Check if Trend Micro is installed and get the product name.
path = NULL;
product = NULL;
titanium = FALSE;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  foreach name (keys(list))
  {
    prod = list[name];

    if (prod && "Trend Micro Worry-Free Business Security Agent" >< prod)
    {
     product = prod;
     break;
    }
    else if (name == "Wofie")
    {
     product = "Trend Micro Worry-Free Business Security Agent";
     break;
    }
    else if (prod && "Trend Micro Client/Server Security Agent" >< prod)
    {
     product = prod;
     break;
    }
    else if (prod && "Trend Micro OfficeScan" >< prod)
    {
     product = prod;
     break;
    }
    else if (prod && "Trend Micro Titanium" >< prod)
    {
     product = prod;
     titanium = TRUE;
     break;
    }
  }
}
if (isnull(product) || "Worry-Free Business Security Agent" >< product)
{
  keys = make_list("SOFTWARE\TrendMicro\Wofie\CurrentVersion", "SOFTWARE\Wow6432Node\TrendMicro\Wofie\CurrentVersion");
  foreach key (keys)
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"Application Path");
      if (!isnull(value))
      {
        path = value[1];
        if (isnull(product)) product = "Trend Micro Worry-Free Business Security Agent";
      }
      RegCloseKey(handle:key_h);
    }
    if (!isnull(product)) break;
  }
}

if (isnull(product) || "Worry-Free Business Security Agent" >!< product)
{
  # If we don't have the product name yet, try to get it from the registry
  if (isnull(product))
  {
    keys = make_list("SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.", "SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.");
    foreach key (keys)
    {
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        value = RegQueryValue(handle:key_h, item:"ProductName");
        if (!isnull(value) && 'Trend Micro OfficeScan' >< value[1])
          product = value[1];
        else if (!isnull(value) && 'Trend Micro WFBSH_Agent' >< value[1])
          product = 'Trend Micro Worry-Free Business Security Services';
        
        RegCloseKey(handle:key_h);
      }
      if (!isnull(product)) break;
    }
  }
  else if("Titanium" >< product){

    key = "SOFTWARE\TrendMicro\Vizor\";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

    if ( ! isnull(key_h) ){
      product = RegQueryValue(handle:key_h, item:"ProductName");
      product = product[1];

      dll_path = RegQueryValue(handle:key_h, item:"ProductPluginPath");
      dll_path = dll_path[1];

      path = RegQueryValue(handle:key_h, item:"ProductPath");
      path = path[1];

      RegCloseKey (handle:key_h);
    }
  }
  else{
    keys = make_list("SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion", "SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion");
    foreach key (keys)
    {
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        value = RegQueryValue(handle:key_h, item:"Application Path");
        if (!isnull(value))
        {
          path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);

          if (isnull(product)) product = "n/a";
        }
        RegCloseKey(handle:key_h);
      }
      if (!isnull(path)) break;
    }
  }
}
if (isnull(product))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  audit(AUDIT_NOT_INST, "Trend Micro Antivirus");
}
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(1, "Failed to determine the installation path for Trend Micro Antivirus.");
}

# Extract info about product, engine, and database.
current_engine_version = NULL;
current_internal_database_version = NULL;
database_date = NULL;
product_version = NULL;
real_time_scan_enabled = NULL;

if ("Worry-Free Business Security Agent" >< product)
{
  keys = make_list("SOFTWARE\TrendMicro\UniClient\1600\Component","SOFTWARE\Wow6432Node\TrendMicro\UniClient\1600\Component");
  foreach key (keys)
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"c2t4");
      if (!isnull(value)) current_engine_version = value[1];

      if (isnull(current_engine_version))
      {
        value = RegQueryValue(handle:key_h, item:"c2t536871168");
        if (!isnull(value)) current_engine_version = value[1];
      }

      value = RegQueryValue(handle:key_h, item:"c3t4");
      if (!isnull(value)) current_internal_database_version = value[1];

      RegCloseKey(handle:key_h);
    }
    if (!isnull(current_engine_version)) break;
  }

  if (current_engine_version)
  {
    keys = make_list("SOFTWARE\TrendMicro\UniClient\1600\Update", "SOFTWARE\Wow6432Node\TrendMicro\UniClient\1600\Update");
    foreach key (keys)
    {
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        value = RegQueryValue(handle:key_h, item:"LastUpdateTime");
        if (!isnull(value)) database_date = strftime("%Y%m%d", value[1]);

        RegCloseKey(handle:key_h);
      }
      if (!isnull(database_date)) break;
    }

    product_version = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Wofie/DisplayVersion");

    key = "SOFTWARE\TrendMicro\UniClient\1600\Scan\Real Time";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"Enable");
      if (!isnull(value)) real_time_scan_enabled = value[1];

      RegCloseKey(handle:key_h);
    }
  }
  else
  {
    keys = make_list("SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.", "SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.");
    foreach key (keys)
    {
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        value = RegQueryValue(handle:key_h, item:"VsAPINT-Ver");
        if (!isnull(value)) current_engine_version = value[1];

        value = RegQueryValue(handle:key_h, item:"InternalPatternVer");
        if (!isnull(value) && value[1] != 0) current_internal_database_version = value[1];

        if (isnull(current_internal_database_version))
        {
          value = RegQueryValue(handle:key_h, item:"InternalNonCrcPatternVer");
          if (!isnull(value) && value[1] != 0) current_internal_database_version = value[1];
        }

        # In some case, the version is stored as an integer
        if ('.' >!< current_internal_database_version)
        {
          value = RegQueryValue(handle:key_h, item:"PatternVer");
          if (!isnull(value))
          {
            matches = eregmatch(pattern:'^([0-9]+)(' + value[1] + ')([0-9]+)$', string:current_internal_database_version);
            if (matches)
            {
              current_internal_database_version = matches[1] + '.' + matches[2] + '.' + matches[3];
            }
          }
        }

        value = RegQueryValue(handle:key_h, item:"PatternDate");
        if (!isnull(value)) database_date = value[1];

        value = RegQueryValue(handle:key_h, item:"TmListen_Ver");
        if (!isnull(value)) product_version = value[1];

        RegCloseKey(handle:key_h);
      }
      if (!isnull(current_engine_version) && !isnull(current_internal_database_version) && !isnull(database_date) && !isnull(product_version)) break;
    }

    keys = make_list("SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Real Time Scan Configuration", "SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Real Time Scan Configuration");
    foreach key (keys)
    {
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        value = RegQueryValue(handle:key_h, item:"Enable");
        if (!isnull(value)) real_time_scan_enabled = value[1];

        RegCloseKey(handle:key_h);
      }
      if (!isnull(real_time_scan_enabled)) break;
    }
  }
}
else if (titanium){
  # Grab major version for titanium based prod in case the file check below doesn't work.
  uninst_key = hotfix_displayname_in_uninstall_key(pattern:string(product));
  if(uninst_key)
  {
    ver = split(uninst_key, sep:"/");
    ver = ver[len(ver)-2];
    ver = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/" + ver + "DisplayVersion";
    ver = get_kb_item(ver);
  }
}
else
{
  # Check for Smart Scan or Conventional Scan
  # If we are unable to get the this, assume conventional
  smart_scan = 0;
  key = "SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\iCRC Scan";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"ScanType");
    if (!isnull(value)) smart_scan = value[1];
  }
  RegCloseKey(handle:key_h);

  keys = make_list("SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.", "SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Misc.");
  foreach key (keys)
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"VsAPINT-Ver");
      if (!isnull(value)) current_engine_version = value[1];

      value = RegQueryValue(handle:key_h, item:"PatternVer");
      if (!isnull(value)) current_database_version = value[1];

      # nb: If Smart scan is set the NonCrc values are used over the normal.
      #     To be on the safe side there is a chance that the expected value
      #     is not set, so we check the other, if the expected is 0.
      #     Order does matter since the wrong date can be in the non-default
      #     value.
      if (smart_scan)
      {
        value = RegQueryValue(handle:key_h, item:"InternalNonCrcPatternVer");
        if (!isnull(value) && value[1] != 0) current_internal_database_version = value[1];

        if (isnull(current_internal_database_version))
        {
          value = RegQueryValue(handle:key_h, item:"InternalPatternVer");
          if (!isnull(value) && value[1] != 0) current_internal_database_version = value[1];
        }

        value = RegQueryValue(handle:key_h, item:"NonCrcPatternDate");
        if (!isnull(value)&& value[1] != 0) database_date = value[1];

        if (isnull(database_date))
        {
          value = RegQueryValue(handle:key_h, item:"PatternDate");
          if (!isnull(value) && value[1] != 0) database_date = value[1];
        }
      }
      else
      {
        value = RegQueryValue(handle:key_h, item:"InternalPatternVer");
        if (!isnull(value) && value[1] != 0) current_internal_database_version = value[1];

        if (isnull(current_internal_database_version))
        {
          value = RegQueryValue(handle:key_h, item:"InternalNonCrcPatternVer");
          if (!isnull(value) && value[1] != 0) current_internal_database_version = value[1];
        }

        value = RegQueryValue(handle:key_h, item:"PatternDate");
        if (!isnull(value)&& value[1] != 0) database_date = value[1];

        if (isnull(database_date))
        {
          value = RegQueryValue(handle:key_h, item:"NonCrcPatternDate");
          if (!isnull(value) && value[1] != 0) database_date = value[1];
        }
      }

      value = RegQueryValue(handle:key_h, item:"ProgramVer");
      if (!isnull(value)) product_version = value[1];

      RegCloseKey(handle:key_h);
    }
    if (!isnull(current_engine_version) && !isnull(current_internal_database_version) && !isnull(database_date) && !isnull(product_version)) break;
  }

  keys = make_list("SOFTWARE\TrendMicro\PC-cillinNTCorp\CurrentVersion\Real Time Scan Configuration", "SOFTWARE\Wow6432Node\TrendMicro\PC-cillinNTCorp\CurrentVersion\Real Time Scan Configuration");
  foreach key (keys)
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"Enable");
      if (!isnull(value)) real_time_scan_enabled = value[1];

       RegCloseKey(handle:key_h);
    }
    if (!isnull(real_time_scan_enabled)) break;
  }
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Make sure the product is still installed.
file_exists = NULL;

if ("Worry-Free Business Security Agent" >< product)
{
  file_exists = hotfix_file_exists(path:path+"\TmListen.exe");
}
else if (titanium)
{
  # grab version from dll
  if(!isnull(dll_path)){
  dll = hotfix_append_path(path:dll_path,value:"DLLforVersionDisplay.dll");
  file_exists = hotfix_file_exists(path:dll);
  ver = hotfix_get_fversion(path:dll);
  hotfix_handle_error(error_code:ver['error'], file:dll, appname:product, exit_on_fail:FALSE);
  ver = ver['value'];
  ver = join(ver, sep:".");
  }
  # separate into display/actual version
  if(ver =~ "^\d+\.\d+\.\d+\.")
  {
  display_ver =  ereg_replace(pattern:"^(\d+\.\d+\.)(\d+\.)(.*)", replace:"\1\3", string:ver);
  actual_ver = ver;
  }
  else
  {
    display_ver = ver;
    actual_ver = ver;
  }
  product_version = display_ver;
}
else
{
  file_exists = hotfix_file_exists(path:path+"\PccNT.exe");
}
NetUseDel(close:FALSE);
if (!file_exists)
{
  NetUseDel();
  audit(AUDIT_UNINST, 'Trend Micro Antivirus');
}

# Save info in the registry. Can be used by another plugin
# Idea from Noam Rathaus
kb_base = "Antivirus/TrendMicro/";

set_kb_item(name:kb_base+"installed", value:TRUE);
if (!isnull(current_engine_version))
  set_kb_item(name:kb_base+"trendmicro_engine_version", value:current_engine_version);
if (!isnull(current_internal_database_version))
  set_kb_item(name:kb_base+"trendmicro_internal_pattern_version", value:str_replace(find:".", replace:"", string:current_internal_database_version));
if (!isnull(database_date)) set_kb_item(name:kb_base+"trendmicro_database_date", value:database_date);
if (!isnull(product_version)) set_kb_item(name:kb_base+"trendmicro_program_version", value:product_version);

# Determine the info reference key
if ('Trend Micro Client/Server Security Agent' >< product)
{
  if (product_version =~ '^16\\.[0-2]($|\\.)')
    refkey = 'wfbs60';
  else if (product_version !~ "^([0-9]|1[0-5])\.") # exit if the version is > 16.x
  {
    NetUseDel();
    exit(1, 'Signature detection for version ' + product_version + ' of ' + product + ' is not supported by Nessus.');
  }
}
else if ('Trend Micro Worry-Free Business Security Agent' >< product)
{
  if (product_version =~ '^7\\.[0-2]($|\\.)')
    refkey = 'wfbs70';
  else if (product_version =~ '^18\\.0($|\\.)')
    refkey = 'wfbs80';
  else if (product_version =~ '^19\\.0\\.')
    refkey = 'wfbs90';
}
else if ('Trend Micro OfficeScan' >< product)
{
  if (product_version =~ '^10\\.0($|\\.)')
    refkey = 'osce100';
  else if (product_version =~ '^10\\.5($|\\.)')
    refkey = 'osce105';
  else if (product_version =~ '^10\\.6($|\\.)')
    refkey = 'osce106';
  else if (product_version =~ '^11\\.0($|\\.)')
    refkey = 'osce110';
  else if (product_version =~ '^12\\.0($|\\.)')
    refkey = 'osce120';
}
else if ('Trend Micro Worry-Free Business Security Services' >< product)
{
  if (product_version =~ '^19\\.[0-1]($|\\.)')
    refkey = 'wfbs90';
  else
  {
    NetUseDel();
    exit(1, 'Signature detection for version ' + product_version + ' of ' + product + ' is not supported by Nessus.');
  }
}
else if (titanium)
{
  refkey = "ttnm";
}
else
{
  NetUseDel();
  exit(1, 'Signature detection for version ' + product_version + ' of ' + product + ' is not supported by Nessus.');
}

# Generate report.
info = get_av_info("trendmicro");
if (isnull(info)) exit(1, "Failed to get Trend Micro Antivirus info from antivirus.inc.");
if (refkey)
{
  last_engine_version = info[refkey]["last_engine_version"];
  datevers = info[refkey]["datevers"];
}

problems = make_list();

if (isnull(current_engine_version)) current_engine_version = 'n/a';
if (isnull(current_internal_database_version)) current_internal_database_version = 'n/a';
if (isnull(database_date)) database_date = 'n/a';
if (isnull(product_version)) product_version = 'n/a';

# Register install and report for titanium.
if(titanium){

  register_install(
  app_name        : "Trend Micro Titanium",
  path            : path,
  version         : display_ver,
  cpe             : "cpe:/a:TrendMicro:Titanium",
  extra           : make_array("Product", product,"Actual Version",actual_ver)
  );

  hotfix_check_fversion_end();
  exit(0 , "Detected " + product + " " + display_ver + " with no known issues to report.");
}


report =
  '\n' + 'Nessus has gathered the following information about the Trend Micro' +
  '\n' + 'Antivirus install on the remote host :' +
  '\n' +
  '\n  Product name        : ' + product +
  '\n  Version             : ' + product_version +
  '\n  Path                : ' + path +
  '\n  Engine version      : ' + current_engine_version +
  '\n  Virus def version   : ' + current_internal_database_version +
  '\n  Virus database date : ' + database_date +
  '\n';

if (current_engine_version == 'n/a')
{
  problems = make_list(problems, 'The engine version could not be determined.');
}
else
{
  if (last_engine_version)
  {
    if (current_engine_version =~ '^[0-9\\.]+$' && last_engine_version =~ '^[0-9\\.]+$')
    {
      if (ver_compare(ver:current_engine_version, fix:last_engine_version, strict:FALSE) < 0)
        problems = make_list(problems, "The virus engine is out-of-date - " + last_engine_version + " is current.");
    }
    else
      problems = make_list(problems, "The engine version is not numeric.");
  }
  else
  {
    item = 'Nessus does not have information currently about Trend Micro ' +
           '\n    ' + product + ' '+ product_version + ' - it may no longer be supported.' +
           '\n';
    problems = make_list(problems, item);
  }
}

if (database_date == 'n/a')
{
  problems = make_list(problems, 'The database date could not be determined.');
}
else if (int(database_date) < (int(datevers)-1))
{
  # We want to check for the updated pattern files, in case
  # the registry is not being updated correctly
  share = hotfix_path2share(path:path);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  # list_dir expects the dir path to not include the share
  dirpath = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1", string:path);

  timestamp = 0;
  file = FindFirstFile(pattern:dirpath + "\icrc$oth.*");

  while (!isnull(file[1]))
  {
     # Get the Epoch time of the date created,
     # we want the time for the most recent pattern file.
     if (!isnull(file[3][0]) && timestamp < file[3][0])
     {
       timestamp = file[3][0]; # 0 should be the date created.
       file_name = file[1]; # Let's track the file name.
     }
     file = FindNextFile(handle:file);
  }

  # Let's convert the timestamp to a format the plugin expects
  if (timestamp == 0) file_date = 0;
  else file_date = strftime('%Y%m%d', timestamp);

  if (!isnull(file_name))
    set_kb_item(name:kb_base+"trendmicro_pattern_file", value:file_name);
  if (!isnull(file_date))
    set_kb_item(name:kb_base+"trendmicro_pattern_file_date", value:file_date);

  # Lets check the file_date now that we have it
  if (file_date < (int(datevers)-1))
  {
    date_prob = "The virus database date is out-of-date - " + datevers + " is current.";

    if (file_date == 0)
    {
      date_prob += '\n    We could not find any pattern files with dates.';
    }
    else
    {
      date_prob += '\n    The most recent pattern file we could find is '+ file_name + '.' +
        '\n    It\'s \'created date\' value is '+ file_date +'.';
    }

    problems = make_list(problems, date_prob);
  }
}
NetUseDel();

services = get_kb_item("SMB/svcs");
if (services)
{
  if ("Worry-Free Business Security Agent" >< product || 'Worry-Free Business Security Services' >< product)
  {
    if ("Trend Micro Solution Platform" >!< services && 'Trend Micro Security Agent Listener' >!< services)
    {
      problems = make_list(problems, "The 'Trend Micro Solution Platform' or 'Trend Micro Security Agent' service is not running.");
    }
  }
  else
  {
    if (
      "OfficeScanNT" >!< services &&
      "OfficeScan NT" >!< services &&
      "Trend Micro Client/Server Security Agent RealTime Scan" >!< services &&
      "Trend Micro Client/Server Security Agent Echtzeitsuche" >!< services  # German Language
    )
    {
      problems = make_list(problems, "The Trend Micro Antivirus service is not running.");
    }
  }
}
else
{
  problems = make_list(problems, "Nessus unable to retrieve a list of running services from the host.");
}

if(!isnull(real_time_scan_enabled) && real_time_scan_enabled == 0)
{
  problems = make_list(problems, "Real-time scanning is disabled.");
}


if (max_index(problems) > 0)
{
  report += '\n';
  if (max_index(problems) == 1) report += 'One problem was uncovered :\n';
  else report += 'Multiple problems were uncovered :\n';

  foreach problem (problems)
    report += '\n  - ' + problem;

  report += '\n\n' + 'As a result, the host might be infected by viruses.' + '\n';
  security_hole(port:port, extra:report);
}
else
{
  set_kb_item (name:kb_base+"description", value:report);
  exit(0, "Detected Trend Micro Antivirus with no known issues to report.");
}
