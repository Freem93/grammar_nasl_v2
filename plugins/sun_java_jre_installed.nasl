#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33545);
  script_version("$Revision: 1.29 $");
  script_cvs_date("$Date: 2016/03/21 16:53:41 $");

  script_name(english:"Oracle Java Runtime Environment (JRE) Detection");
  script_summary(english:"Checks for Oracle/Sun JRE installs.");

  script_set_attribute(attribute:"synopsis", value:
"There is a Java runtime environment installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"One or more instances of Oracle's (formerly Sun's) Java Runtime
Environment (JRE) is installed on the remote host. This may include
private JREs bundled with the Java Development Kit (JDK).");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jre");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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

# Loop over chunks of the jre.exe (JRE 1.1.x)
# or classic\jvm.dll (JRE 1.2.x) files, looking
# for a version string.
function get_old_java_jre_version(handle)
{
  local_var file_contents, version, read_length, offset;

  offset = 0;
  read_length   = 15000;
  file_contents = ReadFile(handle:handle, offset:offset, length:read_length);

  while(file_contents && (strlen(file_contents) > 0))
  {
    file_contents = str_replace(find:raw_string(0), replace:"", string:file_contents);
    if ("Java(tm) Runtime Loader Version " >< file_contents)
    {
      file_contents = strstr(file_contents, 'Java(tm) Runtime Loader Version ') -  'Java(tm) Runtime Loader Version ';
      version = file_contents - strstr(file_contents, '\n');
      return version;
    }

    if ("JDK-" >< file_contents)
    {
      file_contents = strstr(file_contents, 'JDK-') -  'JDK-';
      version = file_contents - strstr(file_contents, '\n');
      return version;
    }

    offset += read_length - 50;
    file_contents = ReadFile(handle:handle, offset:offset, length:read_length);
  }
  return NULL;
}

get_kb_item_or_exit("SMB/Registry/Enumerated");
appname = 'Java Runtime';
arch = get_kb_item("SMB/ARCH");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Identify possible installs.
java_homes = make_array();
runtimes = make_array();
versions = make_array();

keys = make_list(
  "SOFTWARE\JavaSoft\Java Runtime Environment",
  "SOFTWARE\JavaSoft\Java Development Kit",
  "SOFTWARE\JavaSoft\Java Plug-in"
);
foreach key (keys)
{
  subkeys = get_registry_subkeys(handle:hklm, key:key, wow:TRUE);
  if (!empty_or_null(subkeys))
  {
    foreach hive (keys(subkeys))
    {
      foreach subkey (subkeys[hive])
      {
        if (strlen(subkey) && subkey =~ "^[0-9]+\.")
        {
          key2 = hive + '\\' + subkey;
          path = get_registry_value(handle:hklm, item:key2 + "\JavaHome");

          if (!empty_or_null(path))
          {
            java_homes[key2] = path;
            versions[key2] = subkey;

            # Version is handled differently for Java 1.0-1.2
            if (subkey =~ "^1\.[0-2]$")
            {
              runtimes[key2] = java_homes[key2] + "\bin\jre.exe";

              # Get the microversion (JRE 1.1, 1.2)
              item_mv = get_registry_value(handle:hklm, item:key2 + "\MicroVersion");
              if (!empty_or_null(item_mv))
              {
                # Get the updateversion
                item_uv = get_registry_value(handle:hklm, item:key2 + "\UpdateVersion");
                if (!empty_or_null(item_uv))
                  versions[key2] = subkey + '.' + item_mv + '_' + item_uv;
                else
                  versions[key2] = subkey + '.' + item_mv;
              }
            }

            if ('Java Development Kit' >< key2)
              java_homes[key2] += "\jre";

            # Java 1.4.x
            if (subkey =~ "^1\.4($|[^0-9])")
              runtimes[key2] = java_homes[key2] + "\bin\client\jvm.dll";

            # Java 1.6.x / 1.7.x / 1.8.x
            else if (subkey =~ "^1\.[678]($|[^0-9])" || "Java Plug-in" >< key2)
              runtimes[key2] = java_homes[key2] + "\bin\wsdetect.dll";

            else
            {
              file = NULL;

              item = get_registry_value(handle:hklm, item:key2 + "\RuntimeLib");
              if (!empty_or_null(item))
              {
                file = item;

                # GetProductVersion() cannot get version
                # from hotspot\jvm.dll for versions 1.3.x.
                # RunTimeLib registy entry points to that
                # file, but we need to use NPJava11.dll,
                # a file that GetProductVersion() likes.
                if (subkey =~ "^1\.3(\.|$)")
                  file = str_replace(string:file, find:"hotspot\jvm.dll", replace:"NPJava11.dll");
              }

              if ('Java Development Kit' >< key2 || 'Java Plug-in' >< key2)
                runtimes[key2] = java_homes[key2] + "\bin\server\jvm.dll";
              else
                runtimes[key2] = file;
            }
          }
        }
      }
    }
  }
}
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (isnull(runtimes))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, "Java Runtime");
}

# Verify each install and generate a report.
errors = make_list();
info = "";
path_already_seen = make_array();

foreach version (sort(keys(runtimes)))
{
  fileexists          = FALSE;
  pversion            = NULL;
  update              = NULL;
  kb_version          = versions[version];
  transformed_version = NULL;
  path                = NULL;

  file = runtimes[version];
  if (java_homes[version]) path = java_homes[version];
  else
  {
    path = file;
    if ("\bin\client\jvm.dll" >< path) path = path - "\bin\client\jvm.dll";
  }

  if (path_already_seen[path]++) continue;

  share = hotfix_path2share(path:file);
  pversion = hotfix_get_pversion(path:file);
  hotfix_handle_error(error_code:pversion['error'], file:file, appname:appname, exit_on_fail:FALSE);

  if (empty_or_null(pversion['value']) && "wsdetect.dll" >< file)
  {
    file = str_replace(find:"wsdetect.dll", replace:"client\jvm.dll", string:file);
    pversion = hotfix_get_pversion(path:file);
    hotfix_handle_error(error_code:pversion['error'], file:file, appname:appname, exit_on_fail:FALSE);
  }
  else if (empty_or_null(pversion['value']))
  {
    file = str_replace(find:"client\jvm.dll", replace:"server\jvm.dll", string:file);
    pversion = hotfix_get_pversion(path:file);
    hotfix_handle_error(error_code:pversion['error'], file:file, appname:appname, exit_on_fail:FALSE);
  }

  if (!empty_or_null(pversion['value']))
  {
    fileexists = TRUE;
    # 1.3.x returns pversion of form '#, #, #,...'
    pversion = pversion['value'];
    pversion = str_replace(string:pversion, find:", ", replace:".");
    pversion = split(pversion,sep:".", keep:FALSE);

    # 5.0.150.4 => 1.5.0_15
    # 6.0.230.5  => 1.6.0_23

    if(pversion[0] >= 5) # Revisit this line of code when jre/jdk 1.7 or 2.0 is released.
    {
      # 1.7.0_91 and greater needs to be divided by 100
      if (pversion[0] == 7 && pversion[2] >= 9100)
        update = pversion[2]/100;
      else
        update = pversion[2]/10;
      # 7 => 07
      if(update < 10) update = "0"+update;
      transformed_version = "1."+ pversion[0] + "." + pversion[1] + "_" + update;
    }
    else
    {
      if (pversion[0] == 1 && pversion[1] == 3)
        update = pversion[3];
      else
        update = pversion[3]/10;

      if(update < 10) update = "0"+update;
      transformed_version = pversion[0] + "." + pversion[1] + "." + pversion[2] + "_" + update;
    }
  }
  else
  {
    if (kb_version =~ "^1\.[0-2]\.")
    {
      # Try harder; might be old Java JRE with version
      # in a string inside jre.exe or jvm.dll that
      # GetProductVersion() is not picking up.
      login  = kb_smb_login();
      pass   = kb_smb_password();
      domain = kb_smb_domain();

      share = hotfix_path2share(path:file);
      file2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);

      rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
      if (rc != 1)
      {
        errors = make_list(errors, "Failed to access '"+share+"' / can't verify JRE install in '"+path+"'.");
        NetUseDel(close:FALSE);
        continue;
      }

      fh = CreateFile(
        file:file2,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );

      if (!isnull(fh))
      {
        fileexists = TRUE;
        pversion = get_old_java_jre_version(handle:fh);
        transformed_version = pversion;
      }
      CloseFile(handle:fh);
    }
  }

  if (fileexists)
  {
    # If we get product version, save that version in the KB
    # or else use the version from registry.
    if (!isnull(pversion) && !isnull(transformed_version) && transformed_version =~ "^[0-9]+\.")
      kb_version = transformed_version;

    # All we're interested in is whether the runtime exists.
    set_kb_item(name:"SMB/Java/JRE/"+kb_version, value:path);

    register_install(
      app_name:"Java Runtime",
      path:path,
      display_version:kb_version,
      cpe:"cpe:/a:oracle:jre");
  
    info += '\n' +
            '  Path    : ' + path + '\n' +
            '  Version : ' + kb_version + '\n';
  }
}
NetUseDel(close:FALSE);
NetUseDel();

# Report what we found.
if (info)
{
  port = kb_smb_transport();
  set_kb_item(name:"SMB/Java/JRE/Installed", value:TRUE);

  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 3) s = "s of Oracle's JRE are";
    else s = " of Oracle's JRE is";

    report =
      '\n' +
      'The following instance'+s+' installed on the remote\n' +
      'host :\n' +
      info;
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

  if (max_index(errors)) exit(1, "The results may be incomplete because of one or more errors verifying installs.");
  else exit(0);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');

  exit(1, errmsg);
}
else exit(0, "No instances of Oracle Java Runtime were found.");
