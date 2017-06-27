#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(87777);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/06/28 18:08:40 $");

  script_name(english:"Avast Antivirus Detection and Status");
  script_summary(english:"Checks for Avast Antivirus.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
  script_set_attribute(attribute:"description", value:
"Avast Antivirus, a commercial antivirus software package for Windows,
is installed on the remote host. However, there is a problem with the
installation; either its services are not running or its engine and/or
virus definitions are out of date.");
  script_set_attribute(attribute:"see_also", value:"https://www.avast.com");
  script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avast:avast_antivirus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/registry_full_access");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("antivirus.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");
include("datetime.inc");

get_kb_item_or_exit("SMB/registry_full_access");
get_kb_item_or_exit("SMB/Services/Enumerated");

app_name = "Avast Antivirus";
exe = "AvastSvc.exe";

avdefs = "";
last_update = "";
next_update = "";
last_scan = "";
last_scan_time = "";

display_names = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

path = NULL;
foreach key (keys(display_names))
{
  ##
  # New versions of Avast use the name Avast
  # while older versions use the name avast!
  ##
  if ('Avast' >< display_names[key] || 'avast!' >< display_names[key])
  {
    key = key - '/DisplayName';
    key = key + '/InstallLocation';
    path = get_kb_item_or_exit(key);
    break;
  }
}

if (isnull(path)) audit(AUDIT_NOT_INST, app_name);

kb_base = "Antivirus/Apps/Avast/";
port = kb_smb_transport();

file = hotfix_append_path(path:path, value:exe);

if (hotfix_file_exists(path:file))
{
  version = hotfix_get_fversion(path:file);
  hotfix_handle_error(
    error_code:version['error'],
    appname:app_name,
    file:file,
    exit_on_fail:TRUE);
}

hotfix_check_fversion_end();

if (isnull(version))
  audit(AUDIT_UNINST, app_name);

# Build actual Avast Versions
if (version['value'][0] == 11)
{
  vmain = 2016 ;
}
else if (version['value'][0] == 10)
{
  vmain = 2015 ;
}
else if (version['value'][0] == 9)
{
  vmain = 2014 ;
}
else if (version['value'][0] == 8)
{
  vmain = 2013 ;
}

version = join(version['value'], sep:'.');
version = vmain + "." + version ;

defs = path + "\defs\aswdefs.ini";
properties = hotfix_get_file_contents(defs);

hotfix_handle_error(error_code:properties["error"], file:defs, appname:app_name, exit_on_fail:TRUE);

data = properties['data'];
pattern = "Latest=([0-9]+)";
item = eregmatch(pattern:pattern, string:data);
if (!isnull(item))
{
  avdefs = item[1];
}

programdata = hotfix_get_programdata(exit_on_fail:TRUE);
info = programdata + "\AVAST Software\Avast\avast5.ini";
configuration = hotfix_get_file_contents(info);

utf16_str = configuration['data'];

# We need to remove the null character from every other
# byte, starting with the first one. 

decoded_str = '';

for(i=0; i<strlen(utf16_str); i+=2)
  decoded_str += utf16_str[i];

pattern = "LastUpdate=([0-9]+)";
item = eregmatch(pattern:pattern, string:decoded_str);
if(!isnull(item))
{
  last_update = item[1];
}

pattern = "NextUpdate=([0-9]+)";
item = eregmatch(pattern:pattern, string:decoded_str);
if(!isnull(item))
{
  next_update = item[1];
}

pattern = "LastScan=([0-9]+)";
item = eregmatch(pattern:pattern, string:decoded_str);
if(!isnull(item))
{
  last_scan = item[1];
}

pattern = "LastScanTime=([0-9]+)";
item = eregmatch(pattern:pattern, string:decoded_str);
if(!isnull(item))
{
  last_scan_time = item[1];
}

# Generate report
trouble = 0;

report = "The Avast Antivirus System is installed on the remote host :

  Version           : " + version + "
  Installation path : " + path + "
  Virus signatures  : " + avdefs + "
";

info = get_av_info("avast");
if (isnull(info)) exit(1, "Failed to get Avast Antivirus info from antivirus.inc.");
if (!version) exit(1, "Failed to get the Avast Antivirus product version.");

latest_prod_ver = info['win5']["latest_prod_ver"];
latest_sigs_ver = info['latest_sigs_ver'];
curr_update_date = info["update_date"];
latest_sigs_ver = str_replace(string:latest_sigs_ver, find:"-", replace:"0");

if(!empty_or_null(last_update))
{
  last_update_utc = strftime('%Y%m%d', int(last_update));
}
else
{
 last_update_utc = "";
}
  report += "  Last sigs date    : " + last_update_utc + '\n';

# A check to see if AV signature definitions are up to date.
# This function was tested and works.
if (int(avdefs) < int(latest_sigs_ver))
{
  report += "
The virus signatures on the remote host are out-of-date. The last
known update from the vendor is signature number " + latest_sigs_ver + ".";
  trouble++;
}
# A check to see if product version is out of date.
if (version)
{
  if (latest_prod_ver)
  {
    if (ver_compare(ver:version, fix:latest_prod_ver, strict:FALSE) < 0)
    {
      report += '\n' + 'The Avast Antivirus product install is out-of-date. The last known update from the' +
                '\n' + 'the vendor is ' + last_prod_version + '.' +
                '\n';
      trouble++;
    }
  }
  else
    exit(0, "Nessus does not currently have information about Avast Antivirus " + version + " product.");
}

# A check if signatures more than 3 days out of date
curr_update_parts = eregmatch(pattern:"^20(\d{2})(\d{2})(\d{2})$",string:curr_update_date);
curr_update_unix = "";
updateDiff = 0;
if(!empty_or_null(curr_update_parts))
{
  curr_update_unix = utctime_to_unixtime(curr_update_parts[1] + curr_update_parts[2] + curr_update_parts[3] + "000000");
  if(!empty_or_null(last_update))
  {
    updateDiff = int(curr_update_unix) - int(last_update);
    if (int(updateDiff) > 259200)
    {
      trouble++;
      report += '\n' +
            'The virus signatures on the remote host are out-of-date by at least 3 days.\n' +
            'The last update available from the vendor was on ' + curr_update_date  + '.\n';
    }
  }
  else
  {
    trouble++;
    report += '\n' +
          'The virus signatures on the remote host have never been updated!\n' +
          'The last update available from the vendor was on ' + curr_update_date  + '.\n';
  }
}


# - services running.
services = get_kb_item("SMB/svcs");
if (services)
{
  if ("Avast Antivirus" >!< services)
  {
    report += '\nThe Avast Antivirus service (avast! Antivirus) is not running.\n';
    trouble++;
  }
}
else
{
  report += '\nNessus was unable to retrieve a list of running services from the host.\n';
  trouble++;
}

if (trouble) report += '\n' +
                     'As a result, the remote host might be infected by viruses.\n';

if (trouble)
{
  report = '\n' + report ;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report) ;
}
else
{
  # nb: antivirus.nasl uses this in its own report.
  set_kb_item(name:"Antivirus/Avast/description", value:report);
  exit(0, "Detected Avast Antivirus with no known issues to report.");
}

set_kb_item(name:"Antivirus/Avast/installed", value:TRUE);
set_kb_item(name:"Antivirus/Avast/version", value:version);
set_kb_item(name:"Antivirus/Avast/path", value:path);
set_kb_item(name:"Antivirus/Avast/avdefs", value:avdefs);
set_kb_item(name:"Antivirus/Avast/lastupdate", value:last_update);
set_kb_item(name:"Antivirus/Avast/nextupdate", value:next_update);
set_kb_item(name:"Antivirus/Avast/lastscan", value:last_scan);

register_install(
  app_name:app_name,
  path:path,
  version:version,
  cpe:"cpe:/a:avast:avast_antivirus"
);
