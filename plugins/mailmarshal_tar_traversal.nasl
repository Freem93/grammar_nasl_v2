#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26060);
  script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_bugtraq_id(25523);
  script_osvdb_id(38184);

  script_name(english:"MailMarshal tar Archive Traversal Arbitrary File Overwrite");
  script_summary(english:"Checks if MailMarshal uses 7za.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is prone to a directory
traversal attack.");
 script_set_attribute(attribute:"description", value:
"The remote host is running MailMarshal, a mail server for Windows.

According to the registry, the installation of MailMarshal on the
remote Windows host fails to properly sanitize file names when
unpacking tar files. A remote attacker may be able to leverage this
issue to overwrite files and execute arbitrary code. Further, since
the application operates with SYSTEM privileges, this could lead to a
complete compromise of the affected system.");
 script_set_attribute(attribute:"see_also", value:"http://marshal.com/kb/article.aspx?id=11780");
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch for MailMarshal SMTP or MailMarshal
Exchange as described in the vendor advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/30");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/18");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");


function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

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


# Check for each of the affected products.
paths = make_array();
tars = make_array();

prods = make_list(
  "MailMarshal",
  "MailMarshal For Exchange"
);
foreach prod (prods)
{
  path = NULL;
  ver = NULL;

  key = "SOFTWARE\NetIQ\" + prod;
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"InstallPath");
    if (!isnull(value)) path = value[1];

    # nb: MailMarshal's advisory doesn't say an upgrade fixes the issue
    #     but it might be useful to have this in the future.
    value = RegQueryValue(handle:key_h, item:"Version");
    if (!isnull(value)) ver = value[1];

    RegCloseKey(handle:key_h);
  }

  # If so, look for evidence of the fix in the registry.
  tars[prod] = NULL;

  if (!isnull(path))
  {
    paths[prod] = path;
    tar = NULL;

    key += "\Default\Engine";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"TAR");
      if (!isnull(value)) tars[prod] = value[1];

      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);


# Generate a report.
info = "";

foreach prod (keys(paths))
{
  path = paths[prod];
  tar = tars[prod];
  patch = FALSE;

  # If tar is not set...
  if (isnull(tar))
  {
    if (thorough_tests)
    {
      # Make sure the admin didn't overwrite the existing tar.exe with the fix.
      tar = "tar.exe";
    }
    else
    {
      info += 'Nessus did not find evidence of the patch for ' + prod + '\n' +
              'in the registry.\n';
      break;
    }
  }
  # Otherwise...
  else
  {
    # Don't check any further unless we're being paranoid.
    if (report_paranoia < 2) break;

    patch = TRUE;
    tar = ereg_replace(pattern:"^[^;]+;([^ ]+) .+$", replace:"\1", string:tar);
    if (".exe" >!< tar) tar += ".exe";
  }

  # Check the file used to handle tar files.
  tar_name = NULL;
  tar_ver = NULL;

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\"+tar, string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc == 1)
  {
    fh = CreateFile(
      file:exe,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      tar_ver = GetFileVersion(handle:fh);

      ret = GetFileVersionEx(handle:fh);
      if (!isnull(ret)) children = ret['Children'];
      if (!isnull(children))
      {
        varfileinfo = children['VarFileInfo'];
        if (!isnull(varfileinfo))
        {
          translation =
            (get_word(blob:varfileinfo['Translation'], pos:0) << 16) +
            get_word(blob:varfileinfo['Translation'], pos:2);
          translation = toupper(display_dword(dword:translation, nox:TRUE));
        }
        stringfileinfo = children['StringFileInfo'];
        if (!isnull(stringfileinfo) && !isnull(translation))
        {
          data = stringfileinfo[translation];
          if (isnull(data)) data = stringfileinfo[tolower(translation)];
          if (!isnull(data)) tar_name = data['ProductName'];
        }
      }
      CloseFile(handle:fh);
    }
    NetUseDel(close:FALSE);
  }


  if (isnull(tar_name))
  {
    if (FALSE == patch)
    {
      info += 'Nessus did not find evidence of the patch for ' + prod + '\n' +
              'in the registry nor could it determine that the instance of ' + tar + '\n' +
              'in the installation directory was the patched version.\n';
    }
    else
    {
      info += 'While Nessus did find evidence of the patch for ' + prod + '\n' +
              'in the registry, it could not determine that ' + tar + '\n' +
              'in the installation directory was the patched version.\n';
    }
  }
  else if (report_paranoia > 1)
  {
    if ("7-Zip" >!< tar_name)
    {
      info += 'The tar utility (' + tar + ') used by ' + prod + ' is not the\n' +
              'one supplied in the patch -- its product name is ' + tar_name + '\n' +
              'rather than 7-Zip.\n';
    }
    else if (
      tar_ver[0] < 4 ||
      (
        tar_ver[0] == 4 &&
        (
          tar_ver[1] < 53 ||
          (tar_ver[1] == 53 && tar_ver[2] < 3)
        )
      )
    )
    {
      tar_version = string(tar_ver[0] + '.' + tar_ver[1] + '.' + tar_ver[2] + '.' + tar_ver[3]);
      info += 'The tar utility (' + tar + ') used by ' + prod + ' is a version of\n' +
              '7-ZIP earlier than the one supplied in the patch -- ' + tar_version + '\n' +
              'versus 4.53.3.0.\n';
    }
  }
}
NetUseDel();


# Issue a report if appropriate.
if (info)
{
  security_hole(port:port, extra:info);
}
