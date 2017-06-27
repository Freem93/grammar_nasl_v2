#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33268);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2008-2880");
  script_osvdb_id(46518);
  script_bugtraq_id(29932);
  script_xref(name:"Secunia", value:"27995");

  script_name(english:"IBM AFP Viewer Plug-in SRC Property Buffer Overflow");
  script_summary(english:"Checks version of AFP Viewer plug-ins");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a browser plugin that is affected by a
buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The Windows remote host contains IBM's AFP Viewer plug-in, which
allows for viewing AFP (Advanced Function Presentation) documents from
a web browser.

The version of the plug-in installed on the remote host reportedly
contains a heap-based buffer overflow that can be triggered when
processing a 'SRC' property with a string longer than 1023 characters.
If an attacker can trick a user on the affected host into visiting a
specially crafted web page, this issue could be leveraged to execute
arbitrary code on the affected system subject to the user's
privileges.");
  # http://web.archive.org/web/20080918155546/http://www-01.ibm.com/support/docview.wss?rs=95&context=SRNPPZ&q=psd1*&uid=psd1P4000233
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91153f42");
 script_set_attribute(attribute:"solution", value:"Upgrade to AFP Viewer plug-in version 3.4.1.7 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"patch_publication_date", value:"2008/06/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/26");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:afp_viewer_plug-in");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
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
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Locate the plugins
plugins = make_array();

# - ActiveX control
clsid = NULL;

key = "SOFTWARE\Classes\IBM.AfpPlgIn\CLSID";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) clsid = value[1];

  RegCloseKey(handle:key_h);
}
if (!isnull(clsid))
{
  file = NULL;

  key = "SOFTWARE\Classes\CLSID\" + clsid +  "\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) file = value[1];

    RegCloseKey(handle:key_h);
  }
  if (file)
  {
    if (report_paranoia < 2)
    {
      # Check the compatibility flags for the control.
      flags = NULL;

      key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid;
      key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        value = RegQueryValue(handle:key_h, item:"Compatibility Flags");
        if (!isnull(value)) flags = value[1];
        RegCloseKey(handle:key_h);
      }

      if (isnull(flags) || ((flags & 0x400) == 0)) plugins[file] = "ActiveX Control";
    }
    else plugins[file] = "ActiveX Control";
  }
}
# - Firefox.
key = "SOFTWARE\Mozilla";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^Mozilla Firefox ")
    {
      key2 = key + "\" + subkey + "\Extensions";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"Plugins");
        if (!isnull(item))
        {
          file = item[1] + "\NPOAFP32.dll";
          plugins[file] = "Firefox Plugin";
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (max_index(keys(plugins)) == 0)
{
  NetUseDel();
  exit(0);
}


# Determine the version of each instance found.
info = "";

foreach file (keys(plugins))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  file2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
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
    ver = GetFileVersion(handle:fh);
    if (!isnull(ver))
    {
      fix = split("3.4.1.7", sep:'.', keep:FALSE);
      for (i=0; i<max_index(fix); i++)
        fix[i] = int(fix[i]);

      for (i=0; i<max_index(ver); i++)
        if ((ver[i] < fix[i]))
        {
          version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

          info += '  - ' + plugins[file] + ' :\n' +
                  '    ' + file + ', ' + version + '\n';
          break;
        }
        else if (ver[i] > fix[i])
          break;
    }
    CloseFile(handle:fh);
  }
  NetUseDel(close:FALSE);
}
NetUseDel();


# Issue a report if an old version was found.
if (info)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus has identified the following vulnerable instance(s) of the AFP\n",
      "Viewer plug-in installed on the remote host :\n",
      "\n",
      info
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
