#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49675);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"Microsoft Enhanced Mitigation Experience Toolkit (EMET) Installed");
  script_summary(english:"Checks if Microsoft EMET is installed.");

  script_set_attribute(attribute:"synopsis", value:
"A tool for mitigating security vulnerabilities is installed on the
remote system.");
  script_set_attribute(attribute:"description", value:
"Microsoft's Enhanced Mitigation Experience Toolkit (EMET), a tool for
mitigating security vulnerabilities in Windows applications, is
installed on the remote system.");
  # http://blogs.technet.com/b/srd/archive/2010/09/02/enhanced-mitigation-experience-toolkit-emet-v2-0-0.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c1c5f6a");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/24");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:enhanced_mitigation_experience_toolkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("wmi_enum_emet.nbin", "smb_hotfixes.nasl");
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

get_kb_item_or_exit("SMB/Registry/Enumerated");

# First see if we already got the information via WMI
apps_uid = make_array();
apps_settings = make_array(
  'bottomupaslr', 'BottomUpASLR',
  'dep', 'DEP',
  'eaf', 'EAF',
  'heapspray', 'HeapSpray',
  'nullpage', 'NullPage',
  'sehop', 'SEHOP',
  'mandatoryaslr', 'MandatoryASLR',
  'asr', 'ASR'
);

items = get_kb_list("WMI/Microsoft/EMET/*");
if (items)
{
  path = get_kb_item("WMI/Microsoft/EMET/Path");
  foreach item (keys(items))
  {
    if ('Installed' >< item || 'Version' >< item || 'Path' >< item)
      continue;

    app = item - "WMI/Microsoft/EMET/";
    prot = strstr(app, '/') - '/';
    app = app - strstr(app, '/');

    apps_uid[app]['path'] = tolower(app);
    apps_uid[app]['settings'][prot] = items[item];
  }
  registry_init();
}
else
{
  if (!get_kb_item("SMB/Registry/Enumerated"))  audit(AUDIT_KB_MISSING, "SMB/Registry/Enumerated");

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

  hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(hklm))
  {
    NetUseDel();
    audit(AUDIT_REG_FAIL);
  }

  path = NULL;

  # Detect if EMET is installed.
  installstring = NULL;

  list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  if (!isnull(list))
  {
    foreach name (keys(list))
    {
      prod = list[name];
      if (prod && "EMET" >< prod)
      {
        installstring = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(SOFTWARE\/Microsoft\/Windows\/CurrentVersion\/Uninstall\/.+)\/DisplayName$", replace:"\1", string:name);
        installstring = str_replace(find:"/", replace:"\", string:installstring);
        emet_prod = prod;
        break;
      }
    }
  }

  # Try to get InstallLocation from uninstall keys.

  if(!isnull(installstring))
  {
    key = installstring;
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"InstallLocation");
        if (!isnull(value))
          path = value[1];

      RegCloseKey(handle:key_h);
    }
  }

  key = "SOFTWARE\Microsoft\EMET";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);

    for (i=0; i<info[1] ; ++i)
    {
      # exe_name == iexplore.exe
      exe_name = RegEnumKey(handle:key_h, index:i);

      # ignore _settings_
      if (strlen(exe_name) && "_settings_" >!< exe_name)
      {
        key2 = key + "\" + exe_name;
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          info2 = RegQueryInfoKey(handle:key2_h);
          for (j=0; j< info2[0]; ++j)
          {
            value = RegEnumValue(handle:key2_h, index:j);
            if (!isnull(value))
            {
              # subvalue = .exe path
              subvalue = value[1];
              item = RegQueryValue(handle:key2_h, item:subvalue);
              # item[1] = app_uid

              if (!isnull(item) && ereg(pattern:"\{[0-9A-Za-z-]+\}",string:item[1]) && ereg(pattern:"([A-Za-z]:|\*).+\\"+exe_name,string:subvalue,icase:TRUE))
              {
                apps_uid[item[1]]['path'] = tolower(subvalue);
                apps_uid[item[1]]['settings'] = make_array();
              }
            }
          }
          RegCloseKey(handle:key2_h);
        }
      }
    }
    RegCloseKey(handle:key_h);
  }

  # Now query EMET settings, based on the uid.
  key = "SOFTWARE\Microsoft\EMET\_settings_";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; ++i)
    {
      uid = RegEnumKey(handle:key_h, index:i);
      if (strlen(uid) && ereg(pattern:"\{[0-9A-Za-z-]+\}",string:uid))
      {
        key2 = key + "\" + uid;

        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          # this feature is apparently the same (introduced as BottomUpRand in 2.1 and renamed to BottomUpASLR in 3.0)
          value = RegQueryValue(handle:key2_h, item:"BottomUpRand");
          if (!isnull(value)) apps_uid[uid]['settings']['bottomupaslr'] = value[1];
          value = RegQueryValue(handle:key2_h, item:"BottomUpASLR");
          if (!isnull(value)) apps_uid[uid]['settings']['bottomupaslr'] = value[1];
          else apps_uid[uid]['settings']['bottomupaslr'] = 0;

          value = RegQueryValue(handle:key2_h, item:"DEP");
          if (!isnull(value)) apps_uid[uid]['settings']['dep'] = value[1];
          else apps_uid[uid]['settings']['dep'] = 0;

          value = RegQueryValue(handle:key2_h, item:"EAF");
          if (!isnull(value)) apps_uid[uid]['settings']['eaf'] = value[1];
          else apps_uid[uid]['settings']['eaf'] = 0;

	  value = RegQueryValue(handle:key2_h, item:"ASR");
          if (!isnull(value)) apps_uid[uid]['settings']['ASR'] = value[1];
          else apps_uid[uid]['settings']['ASR'] = 0;

          value = RegQueryValue(handle:key2_h, item:"HeapSpray");
          if (!isnull(value)) apps_uid[uid]['settings']['heapspray'] = value[1];
          else apps_uid[uid]['settings']['heapspray'] = 0;

          value = RegQueryValue(handle:key2_h, item:"NullPage");
          if (!isnull(value)) apps_uid[uid]['settings']['nullpage'] = value[1];
          else apps_uid[uid]['settings']['nullpage'] = 0;

          value = RegQueryValue(handle:key2_h, item:"SEHOP");
          if (!isnull(value)) apps_uid[uid]['settings']['sehop'] = value[1];
          else apps_uid[uid]['settings']['sehop'] = 0;

          # Only available on vista and later.
          value = RegQueryValue(handle:key2_h, item:"MandatoryASLR");
          if (!isnull(value)) apps_uid[uid]['settings']['mandatoryaslr'] = value[1];
          else apps_uid[uid]['settings']['mandatoryaslr'] = 0;

          RegCloseKey(handle:key2_h);
        }
      }
    }
    RegCloseKey(handle:key_h);
  }
  RegCloseKey(handle:hklm);
}

# InstallLocation is not set in v2.0, so hardcode path.
if(isnull(path) && !isnull(emet_prod))
{
  # EMET 4.1 Update 1 shows up as such in the uninstall, which leads
  # to a bad path being calculated below. So we'll tweak things a bit
  # here.
  pattern = "(EMET \d+(?:\.\d+)*)( Update \d+)?";
  match = eregmatch(string:prod, pattern:pattern);
  if (!isnull(match)) prod = match[1];

  # this will work for now (detecting EMET on 64 and 32 bit hosts respectively)
  # but will not work on 64 bit hosts if a 64 bit release of EMET is ever made
  if (hotfix_get_programfilesdirx86())
    path = hotfix_get_programfilesdirx86() + "\" + prod;
  else if (hotfix_get_programfilesdir())
    path = hotfix_get_programfilesdir() + "\" + prod;
}

if (isnull(path))
{
  NetUseDel();
  exit(1,"EMET is not installed or it was not possible to determine its install path.");
}
NetUseDel(close:FALSE);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\EMET_GUI.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(file:exe,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

ver = NULL;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
else
{
 NetUseDel();
 exit(0,"File "+(share-'$')+":"+exe+" does not exist.");
}

NetUseDel();

info = '';

# Check the version number.
if (!isnull(ver))
{
  # Ok, so EMET exe exists.
  # Now set the KB's.
  kb_base = "SMB/Microsoft/EMET";

  set_kb_item(name:kb_base + "/Installed", value:TRUE);
  set_kb_item(name:kb_base + "/Version", value:join(ver, sep:"."));
  set_kb_item(name:kb_base + "/Path", value:path);

  foreach uid (keys(apps_uid))
  {
    info2 = '';
    # app = acrord32.exe = apps_uid[{d1c65a5f-d067-4b64-9b77-d8967f0e9de5}]
    app = apps_uid[uid]['path'];
    foreach setting (keys(apps_uid[uid]['settings']))
    {
      set_kb_item(name:kb_base + "/" + app + "/" + setting, value:apps_uid[uid]['settings'][setting]);
      info2 += apps_settings[setting] + " : " + apps_uid[uid]['settings'][setting] + " ";
    }

    if(info2)
      info += "+ " + app + " -> " + info2 + '\n';
  }

  if(report_verbosity > 0)
  {
    report =
      '\n' +
      '  Product : Enhanced Mitigation Experience Toolkit (EMET)' + '\n' +
      '  Path    : ' + path + '\n' +
      '  Version : ' + join(ver, sep:".") + '\n' ;

    if(report_verbosity > 1 && info)
      report += '\n' +
        "Following apps are configured to use EMET as follows :" +'\n\n' +
        info;
     security_note(port:port, extra:report);
  }
  else
    security_note(port:port);
}
else exit(1, "Couldn't get file version of '"+(share-'$')+":"+exe+"'.");

