#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62075);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/07/12 02:12:31 $");

  script_name(english:"Check Point Endpoint Security Remote Access Client Installed");
  script_summary(english:"Checks for Check Point Remote Access Client");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a VPN client installed.");
  script_set_attribute(attribute:"description", value:
"Check Point Endpoint Security Remote Access Client, a software VPN
client, is installed on the remote Windows host.");
   # https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doShowproductpage&productTab=overview&product=175
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6d1af114");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:checkpoint:remote_access_clients");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

appname = 'Check Point Endpoint Security Remote Access Client';
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\CheckPoint\TRAC";
subkeys = get_registry_subkeys(handle:hklm, key:key);
paths = make_list();

foreach subkey (subkeys)
{
  if (subkey =~ '^[0-9\\.]+$')
  {
    entry = key + '\\' + subkey + "\PRODDIR";
    path = get_registry_value(handle:hklm, item:entry);

    if (!isnull(path)) paths = make_list(paths, path);
  }
}

RegCloseKey(handle:hklm);

if (max_index(paths) == 0)
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

report = '';
installs = 0;
errors = make_list();
foreach path (paths)
{
  ver = NULL;
  verui = NULL;
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
  exe1 = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\TracSrvWrapper.exe", string:path);
  exe2 = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\TrGUI.exe", string:path);

  NetUseDel(close:FALSE);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    errors = make_list(errors, "Failed to access '"+share+"' / can't verify Check Point RAC install in '"+path+"'.");
    NetUseDel(close:FALSE);
    continue;
  }

  fh1 = CreateFile(
    file:exe1,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh1)) continue;
  ver = GetFileVersion(handle:fh1);
  if (isnull(ver))
  {
    version = 'Unknown';
    errors = make_list(errors, "Failed to get the version of '"+path+"\TracSrvWrapper.exe'.");
  }
  else
  {
    installs++;
    version = join(ver, sep:'.');
    set_kb_item(name:'SMB/Check Point Remote Access Client/'+version+'/Path', value:path);
    # Try to get the UI version
    fh2 = CreateFile(
      file:exe2,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh2))
    {
      verui = GetProductVersion(handle:fh2);
      if (isnull(verui))
      {
        verui = 'Unknown';
      }
      else
      {
        if ('VPN ' >< verui) verui = verui - 'VPN ';
        set_kb_item(name:'SMB/Check Point Remote Access Client/'+version+'/VerUI', value:verui);
      }
      CloseFile(handle:fh2);
    }
    else verui = 'Unknown';

    register_install(
      app_name:appname,
      path:path,
      version:version,
      display_version:verui,
      cpe:"cpe:/a:checkpoint:remote_access_clients");
  }
  CloseFile(handle:fh1);
  report +=
    '\n  Path        : ' + path +
    '\n  Version     : ' + verui + '\n';
}
NetUseDel();

if (!installs) audit(AUDIT_UNINST, appname);

if (report)
{
  set_kb_item(name:'SMB/Check Point Remote Access Client/Installed', value:TRUE);
  if (report_verbosity > 0)
  {
    if (installs > 1) s = 's of Check Point Remote Access Client were found ';
    else s = ' of Check Point Remote Access Client was found ';
    report =
      '\n  The following install' + s + 'on the' +
      '\n  remote host :' +
      '\n' +
      report;

    if (max_index(errors))
    {
      report +=
        '\n' +
        'Note that the results may be incomplete because of the following ';

      if (max_index(errors) == 1) report += 'error\nthat was';
      else report += 'errors\nthat were';

      report +=
        ' encountered :\n' +
        '\n' +
        '  ' + join(errors, sep:'\n  ') + '\n';
    }
    security_note(port:port, extra:report);
  }
  else security_note(port);

  if (max_index(errors)) exit(1, 'The results may be incomplete because of one or more errors verifying installs.');
  else exit(0);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');

  exit(1, errmsg);
}
else audit(AUDIT_NOT_DETECT, appname);
