#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12215);
  script_version("$Revision: 1.1421 $");
  script_cvs_date("$Date: 2017/03/30 20:16:33 $");

  script_name(english:"Sophos Anti-Virus Detection and Status");
  script_summary(english:"Checks for Sophos Anti-Virus.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Sophos Anti-Virus, a commercial antivirus software package for
Windows, is installed on the remote host. However, there is a problem
with the installation; either its services are not running or its
engine and/or virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"http://www.sophos.com");
  script_set_attribute(attribute:"see_also", value:"https://www.sophos.com/en-us/support/knowledgebase/121984.aspx");
  script_set_attribute(attribute:"see_also", value:"https://downloads.sophos.com/downloads/info/latest_IDE.xml");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2004-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl", "wmi_process_on_port.nbin");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access", "SMB/transport", "SMB/Services/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

appname = "Sophos Anti-Virus";
isUtm = FALSE;
isHome = FALSE;

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

path = NULL;

# Have to check both SOFTWARE\Sophos\SAVService\Application and its
# Wow6432Node manually, as Sophos installs can often leave empty or
# near-empty SOFTWARE\Sophos\SAVService\Application keys even with
# Wow6432Node data that can break our default parsing of the registry.
key_list = make_list("SOFTWARE\Sophos\SAVService\Application", "SOFTWARE\Wow6432Node\Sophos\SAVService\Application");
foreach key (key_list)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    # Defeat Sophos Cloud AV versions, which aren't versioned according to Sophos' own standards
    value = RegQueryValue(handle:key_h, item:"MarketingVersion");
    if (!isnull(value))
    {
      marketing_version = value[1];
      if ("Cloud" >< marketing_version)
      {
        RegCloseKey(handle:hklm);
        NetUseDel();
        exit(0, "The Sophos Anti-Virus install is cloud managed.");
      }
      # is it managed?
      if ("UTM" >< toupper(marketing_version))
        isUtm = TRUE;
    }

    # double-check to see if it is managed
    managed = RegQueryValue(handle:key_h, item:"Managed");
    if (!isnull(managed) && managed[1] == 1)
    {
      isUtm = TRUE;
    }

    if (isnull(path))
    {
      # Determine where it's installed.
      value = RegQueryValue(handle:key_h, item:"Path");
      if (!isnull(value))
      {
        path = value[1];
        path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);

        set_kb_item(name:"Antivirus/Sophos/installed", value:TRUE);
        set_kb_item(name:"Antivirus/Sophos/path", value:path);
      }
    }
    RegCloseKey(handle:key_h);
  }
}

if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  audit(AUDIT_NOT_INST, appname);
}

update_path = NULL;

# Have to check both SOFTWARE\Sophos\AutoUpdate and its Wow6432Node
# manually, as Sophos installs can often leave empty or near-empty
# SOFTWARE\Sophos\AutoUpdate keys even with Wow6432Node data
# that can break our default parsing of the registry.
key_list = make_list("SOFTWARE\Sophos\AutoUpdate", "SOFTWARE\Wow6432Node\Sophos\AutoUpdate");
foreach key (key_list)
{
  if (isnull(update_path))
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"Data Path");
      if (!isnull(value))
      {
        update_path = value[1];
        update_path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:update_path);
      }

      RegCloseKey(handle:key_h);
    }
  }
}

# Determine the software version.
prod_ver = NULL;

list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (!isnull(list))
{
  # Use the installer's registry settings.
  foreach name (keys(list))
  {
    prod = list[name];
    if (prod && "Sophos Anti-Virus" >< prod)
    {
      key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
      key = str_replace(find:"/", replace:"\", string:key);

      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        value = RegQueryValue(handle:key_h, item:"DisplayVersion");
        if (!isnull(value)) prod_ver = value[1];
        RegCloseKey(handle:key_h);
      }
      if (!isnull(prod_ver)) break;
    }
  }
}
RegCloseKey(handle:hklm);

# Find the engine version from veex.dll
eng_ver = NULL;

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\veex.dll", string:path);
if(update_path)
  status_file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\data\status\status.xml", string:update_path);
else
  status_file =  ereg_replace(pattern:"^[A-Za-z]:(.+)\Sophos Anti-Virus", replace:"\1\AutoUpdate\data\status\status.xml", string:path);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

# Check to see if Sophos Home
home_exe = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Sophos UI\SophosUI.exe", string:path);
fh = CreateFile(
  file:home_exe,
  desired_access:GENERIC_READ,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

if (!isnull(fh))
{
  productName = GetProductName(handle:fh);
  CloseFile(handle:fh);
  if (!empty_or_null(productName))
  {
    if ("sophos home" >< tolower(productName))
    {
      isUtm = FALSE;
      isHome = TRUE; # this is the home edition
    }
  }
}

if (isUtm)       appname += " (UTM)";
else if (isHome) appname += " (Home)";

fh = CreateFile(
  file:dll_file,
  desired_access:GENERIC_READ,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

 if (!isnull(fh))
 {
   v = GetFileVersion(handle:fh);
   CloseFile(handle:fh);

   if (!isnull(v))
   {
    eng_ver = v[0] + "." + v[1] + "." + v[2] + "." + v[3];
   }
 }

 CloseFile(handle:fh);

# Now get the last update date from status.xml

last_update_date = NULL;

fh = CreateFile(
  file               : status_file,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);
if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);
  if (fsize)
  {
    # nb: 30K is an arbitrary limit; 10K can be problematic.
    if (fsize > 30720) fsize = 30720;

    data = ReadFile(handle:fh, length:fsize, offset:0);
    if (data && '<LastConnectedTime>' >< data)
    {
      last_update_date = strstr(data, '<LastConnectedTime>') - '</LastConnectedTime>';
      last_update_date = last_update_date - strstr(last_update_date, '\n');
      if (last_update_date)
      {
        last_update_date = chomp(last_update_date);
        last_update_date = ereg_replace(pattern:"^<LastConnectedTime>([0-9]{8})[A-Z][0-9]+$",string:last_update_date, replace: "\1");
      }
    }
  }
}

info = get_av_info("sophos");
if (isnull(info)) exit(1, "Failed to get Sophos Anti-Virus info from antivirus.inc.");

has_latest_ide = FALSE;  # latest antivirus identity file
ide_reason = 'N/A';
latest_ide_md5_match = FALSE;
identity_full_filepath = '';

# if null, let's look for IDE data
if (empty_or_null(last_update_date))
{
  # get latest IDE data from antivirus.inc
  # https://www.sophos.com/en-us/support/knowledgebase/121984.aspx
  # see https://downloads.sophos.com/downloads/info/latest_IDE.xml
  identity_filename = info['update_file'];
  identity_md5 = info['update_md5'];

  if (!empty_or_null(identity_filename) && !empty_or_null(identity_md5))
  {
    # remove the drive prefix from the path
    dirpath = ereg_replace(
      pattern  : "^[A-Za-z]:(.+)$",
      replace  : "\1",
      string   : path
    );

    identity_full_filepath = path + "\" + identity_filename;  # used for reporting
    identity_filepath = dirpath + "\" + identity_filename;

    fh = CreateFile(
      file               : identity_filepath,
      desired_access     : GENERIC_READ,
      file_attributes    : FILE_ATTRIBUTE_NORMAL,
      share_mode         : FILE_SHARE_READ,
      create_disposition : OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      fsize = GetFileSize(handle:fh);
      if (fsize)
      {
        data = ReadFile(handle:fh, length:fsize, offset:0);
        if (data)
        {
          has_latest_ide = TRUE;
          # ensure file integrity
          hash = MD5(data);
          if (hexstr(hash) == identity_md5)
            latest_ide_md5_match = TRUE;
        }
        else
          ide_reason = "Failed to read latest virus identity file.";
      }
      else
        ide_reason = "Latest virus identity file has no data.";
    }
    else
      ide_reason = "Failed to open latest virus identity file.";
  }
  else
    exit(1, "Failed to get latest identity file name or MD5 hash from Antivirus.inc.");
}

CloseFile(handle:fh);

NetUseDel();

# Generate report.
if (!prod_ver) exit(1, "Failed to get the Sophos Anti-Virus product version.");
# Sophos will sometimes have three levels of detail in a single version, sometimes two. Adapting for both.
product_match = eregmatch(pattern:"^([0-9]+\.[0-9]+\.[0-9]+).*$", string:prod_ver);
# Check if we had a result for three levels of depth.
if (isnull(product_match) || isnull(info[product_match[1]]["latest_prod_ver"]))
{
  # Three levels of depth unavailable for this version. Try two!
  product_match = eregmatch(pattern:"^([0-9]+\.[0-9]+).*$", string:prod_ver);
  if (isnull(product_match)) audit(AUDIT_UNKNOWN_APP_VER, appname);
}
prod = product_match[1];
latest_prod_ver = info[prod]["latest_prod_ver"];
latest_eng_ver = info[prod]["latest_eng_ver"];
update_date = info["update_date"];

# If we don't have info on this version, check the lowest version and see if this is greater.
lowest_prod = NULL;
lowest_eng = NULL;
valid_engines = make_array();

foreach inc_prod (keys(info))
{
  # skip update_date/file/md5 keys
  if (inc_prod == "update_date" || inc_prod == "update_file" || inc_prod == "update_md5") continue;
  # Check if lowest prod version
  if (isnull(lowest_prod))
  {
    lowest_prod = inc_prod;
  }
  else if (ver_compare(ver:lowest_prod, fix:inc_prod, strict:FALSE) > 0)
  {
    lowest_prod = inc_prod;
  }
  # Store engine version, check for lowest engine version
  inc_eng = info[inc_prod]["latest_eng_ver"];
  valid_engines[inc_eng] = 1;
  if (isnull(lowest_eng))
  {
    lowest_eng = inc_eng;
  }
  else if (ver_compare(ver:lowest_eng, fix:inc_eng, strict:FALSE) > 0)
  {
    lowest_eng = inc_eng;
  }
}
# Set latest_eng_ver to whatever the lowest_prod version's engine version is
# if it isn't already set. Not currently used.
if(!latest_eng_ver && lowest_prod)
{
  latest_eng_ver = info[lowest_prod]["latest_eng_ver"];
}

trouble = 0;

# - general info.
info = appname + ' is installed on the remote host :\n' +
       '\n' +
       '  Installation path : ' + path + '\n';
if (prod_ver)
{
  info += '  Product version   : ' + prod_ver + '\n';
  set_kb_item(name:"Antivirus/Sophos/prod_ver", value:prod_ver);
}
if (eng_ver)
{
  info += '  Engine version    : ' + eng_ver  + '\n';
  set_kb_item(name:"Antivirus/Sophos/eng_ver", value:eng_ver);
}


register_install(
  app_name:"Sophos Anti-Virus",
  path:path,
  version:prod_ver,
  cpe:"cpe:/a:sophos:sophos_anti-virus");

if (isUtm)
{
  set_kb_item (name:"Antivirus/Sophos/UTM", value:true); # managed by UTM
  # Temporarily disable engine and sig checks for UTM
  # Currently UTM is causing off and on again false positives
  exit(0, "Sophos Anti-Virus UTM is currently not supported.");
}

# - product out of date?
if (prod_ver)
{
  if (latest_prod_ver)
  {
    if (ver_compare(ver:prod_ver, fix:latest_prod_ver, strict:FALSE) < 0)
    {
      info += '\n' + 'The Sophos ' + prod + ' installation is out-of-date. The last known update from' +
              '\n' + 'the vendor is ' + latest_prod_ver + '.' +
              '\n';
      trouble++;
    }
  }
  else if (ver_compare(ver:lowest_prod, fix:prod_ver, strict:FALSE) > 0)
  {
      info += '\n' + 'Nessus does not currently have information about Sophos ' + prod_ver + '. It may no' +
              '\n' + 'longer be supported.' +
              '\n';
      trouble++;
  }
}

# - engine version out of date?
if (eng_ver)
{
  # Alerting if prod_ver is unset should also handle cases in which eng_ver is unset.
  eng_short_match = eregmatch(pattern:"^([0-9]+\.[0-9]+).*$", string:eng_ver);
  if (isnull(eng_short_match))
  {
    eng_short = eng_ver;
  }
  else
  {
    eng_short = eng_short_match[1];
  }
  if (isnull(valid_engines[eng_short]))
  {
    if (ver_compare(ver:eng_ver, fix:lowest_eng, strict:FALSE) < 0)
    {
      info += '\n' + 'The engine version is out-of-date. The oldest supported version from' +
              '\n' + 'the vendor is ' + lowest_eng + '.' +
              '\n';
      trouble++;
    }
  }
}

if (!empty_or_null(last_update_date))
{
  info += '  Virus signatures last updated   : ';
  if (last_update_date) info += substr(last_update_date, 0, 3) + "/" + substr(last_update_date, 4, 5) + "/" + substr(last_update_date, 6, 7) + '\n';
  else info += 'never\n';

  # Check if signatures more than 3 days out of date
  # update date format is YYYYMMDD. last_update_date format is YYYYMMDD.
  report_date = substr(last_update_date, 0, 3) + "/" + substr(last_update_date, 4, 5) + "/" + substr(last_update_date, 6,7);
  vendor_date = substr(update_date, 0, 3) + "/" + substr(update_date, 4, 5) + "/" + substr(update_date, 6,7);
  info += 'Virus signatures last updated   : ' + report_date + '\n';

  latest_time_parts = eregmatch(pattern:"^(\d{4})(\d{2})(\d{2})$", string:update_date);
  if(!isnull(latest_time_parts))
    latest_epoch = mktime(year:int(latest_time_parts[1]), mon:int(latest_time_parts[2]), mday:int(latest_time_parts[3]));
  update_time_parts = eregmatch(pattern:"^(\d{4})(\d{2})(\d{2})$", string:last_update_date);
  if(!isnull(update_time_parts))
    update_epoch = mktime(year:int(update_time_parts[1]), mon:int(update_time_parts[2]), mday:int(update_time_parts[3]));
  three_days = 60*60*24*3;

  if (!isnull(update_epoch))
  {
    # Report if the difference is more than 3 days.
    if ( (latest_epoch - update_epoch) >= three_days)
    {
      trouble++;
      info += '\n' +
              'The virus signatures on the remote host are out-of-date by at least 3 days.\n' +
              'The last update from the vendor was on ' + vendor_date + '.\n';
    }
  }
  else
  {
    trouble++;
    info += '\n' +
            'The virus signatures on the remote host have never been updated!\n' +
            'The last update from the vendor was on ' + vendor_date + '.\n';
  }
}
else
{
  # check to see if we found latest virus identity files (IDE)
  if (has_latest_ide)
  {
    if (!latest_ide_md5_match)
    {
      info += '\n' +
              'The checksum of the latest virus identity file found on the remote host is invalid.\n' +
              'This means that it could have been altered!';
      trouble++;
    }

  }
  else
  {
    info += '\n' + ide_reason; # output reason why latest ide couldn't be found/read
    trouble++;
  }

  if (!isnull(identity_full_filepath))
  {
    info += '\n' +
            '\nNote that Nessus checked for the existence of the following file :\n' +
            "'" + identity_full_filepath + "'" + '\n';
  }
}

# - Check that antivirus service or .exe is running
services = get_kb_item("SMB/svcs");
tasklist = get_kb_item("Host/Windows/tasklist_svc");
if (services || tasklist)
{
  if ("SAVService" >!< services && "SavService.exe" >!< tasklist)
  {
    info += '\nThe Sophos Anti-Virus service (SAVService) is not running.\n';
    trouble++;
  }
}
else
{
  info += '\nNessus was unable to retrieve a list of running services from the host.\n';
  trouble++;
}

if (trouble) info += '\n' +
                     'As a result, the remote host might be infected by viruses.\n';

if (trouble)
{
  report = '\n' + info;
  security_hole(port:port, extra:report);
}
else
{
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item (name:"Antivirus/Sophos/description", value:info);
  exit(0, "Detected " + appname + " with no known issues to report.");
}
