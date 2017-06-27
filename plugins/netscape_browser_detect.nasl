#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(19695);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"Netscape Browser Detection");
  script_summary(english:"Detects Netscape browser");

 script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains a web browser.");
 script_set_attribute(attribute:"description", value:
"There is at least one instance of Netscape Browser / Navigator
installed on the remote Windows host.");
   # http://web.archive.org/web/20110727102956/http://browser.netscape.com/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2d74939");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/14");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:netscape:navigator");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
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
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();

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


# Locate installs.
files = make_array();

foreach soft (make_list("Mozilla", "Netscape"))
{
  key = "SOFTWARE\" + soft;
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    info = RegQueryInfoKey(handle:key_h);
    for (i=0; i<info[1]; ++i)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if (strlen(subkey) && subkey =~ "^Netscape")
      {
        key2 = key + "\" + subkey;
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h))
        {
          info2 = RegQueryInfoKey(handle:key2_h);
          for (j=0; j<info2[1]; ++j)
          {
            subkey2 = RegEnumKey(handle:key2_h, index:j);
            if (strlen(subkey2) && subkey2 =~ "^[0-9]+\.")
            {
              key3 = key2 + "\" + subkey2 + "\Main";
              key3_h = RegOpenKey(handle:hklm, key:key3, mode:MAXIMUM_ALLOWED);
              if (!isnull(key3_h))
              {
                if (subkey2 =~ "^4\.") item = "Install Directory";
                else item = "PathToExe";

                val = RegQueryValue(handle:key3_h, item:item);
                if (!isnull(val))
                {
                  file = val[1];
                  if (subkey2 =~ "^4\.") file += "\Program\netscape.exe";

                  if (" (" >< subkey2) ver = subkey2 - strstr(subkey2, " (");
                  else ver = subkey2;

                  files[file] = ver;
                }
                RegCloseKey(handle:key3_h);
              }
            }
          }
          RegCloseKey(handle:key2_h);
        }
      }
    }
    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);


# Determine the version of each instance found.
info = "";

foreach file (keys(files))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  file2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL,share);
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
    ver = NULL;

    filever = GetFileVersion(handle:fh);
    ret = GetFileVersionEx(handle:fh);
    CloseFile(handle:fh);

    if (!isnull(ret))
    {
      children = ret['Children'];
      if (!isnull(children))
      {
        varfileinfo = children['VarFileInfo'];
        if (!isnull(varfileinfo))
        {
          translation =
            (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
            get_word (blob:varfileinfo['Translation'], pos:2);
          translation = tolower(display_dword(dword:translation, nox:TRUE));
        }
        stringfileinfo = children['StringFileInfo'];
        if (!isnull(stringfileinfo) && !isnull(translation))
        {
          data = stringfileinfo[translation];
          if (!isnull(data)) ver = data['ProductVersion'];
        }
      }
    }
    if (isnull(ver) && !isnull(filever)) ver = string(filever[0], ".", filever[1]);

    if (!isnull(ver))
    {
      if (ver =~ "^9\.")
      {
        info += '  - Netscape Navigator ' + ver + ' :\n';
      }
      else if (ver =~ "^8\." || "Personal" == ver)
      {
        if ("Personal" == ver) ver = files[file];
        ver2 = ereg_replace(pattern:"^([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+$", replace:"\1", string:ver);

        info += '  - Netscape Browser ' + ver2 + ' :\n';
      }
      else if (ver =~ "^[67]\.")
      {
        info += '  - Netscape ' + ver + ' :\n';
      }
      else if (ver =~ "^4\.")
      {
        info += '  - Netscape Navigator ' + ver + ' :\n';
      }
      else
      {
        info += '  - an unknown type of Netscape (version ' + ver + ') :\n';
      }

      info += '    ' + file + '\n';

      set_kb_item(name:"SMB/Netscape/"+ver, value:file);
    }
  }
  NetUseDel(close:FALSE);
}
NetUseDel();


# Issue a report.
if (info)
{
  set_kb_item(name:"SMB/Netscape/installed" , value:TRUE);

  report = string(
    "Nessus detected the following instances of Netscape's browser on the\n",
    "remote host :\n",
    "\n",
    info
  );
  security_note(port:kb_smb_transport(), extra:report);
}
