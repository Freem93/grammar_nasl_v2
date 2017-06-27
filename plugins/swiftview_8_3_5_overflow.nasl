#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(30133);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_cve_id("CVE-2007-5602");
  script_bugtraq_id(27527);
  script_osvdb_id(42836, 42837);
  script_xref(name:"CERT", value:"639169");

  script_name(english:"SwiftView Viewer Plugin < 8.3.5 Buffer Overflow");
  script_summary(english:"Checks versions of SwiftView Viewer plugins");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a browser enhancement that is
affected by a buffer overflow.");
 script_set_attribute(attribute:"description", value:
"A SwiftView Viewer ActiveX control and/or browser plug-in is installed
on the remote Windows host. SwiftView Viewer is an application for
viewing and printing print streams.

According to its version, the SwiftView ActiveX control / browser
plug-in currently installed is affected by a stack-based buffer
overflow. If a remote attacker can trick a user on the affected host
into visiting a specially crafted web page, this issue could be
leveraged to execute arbitrary code on the affected host subject to
the user's privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.swiftview.com/tech/security/bulletins/SBSV-07-10-02.htm");
 script_set_attribute(attribute:"solution", value:"Upgrade to SwiftView Viewer version 8.3.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/31");

script_set_attribute(attribute:"plugin_type", value:"local");
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


# Check whether it's installed.
variants = make_array();

# - check for the browser plugin.
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
          file = item[1] + "\npsview.dll";
          variants[file] = "Plugin";
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
# - check for the ActiveX control.
clsid = "{7DD62E58-5FA8-11D2-AFB7-00104B64F126}";

key = "SOFTWARE\Classes\CLSID\" + clsid + "\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item))
  {
    file = item[1];

    # Only worry about it if the kill bit is not set or we're being paranoid.
    killbit = FALSE;
    if (report_paranoia < 2)
    {
      # Check the compatibility flags for the control.
      key2 = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item2 = RegQueryValue(handle:key2_h, item:"Compatibility Flags");
        if (!isnull(item2)) killbit = (item2[1] & 0x400) == 0x400;

        RegCloseKey(handle:key2_h);
      }
    }
    if (!killbit) variants[file] = "ActiveX";
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (max_index(keys(variants)) == 0)
{
  NetUseDel();
  exit(0);
}


# Determine the version of each instance found.
info = "";

foreach file (keys(variants))
{
  variant = variants[file];

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
      fix = split("8.3.5.0", sep:'.', keep:FALSE);
      for (i=0; i<max_index(fix); i++)
        fix[i] = int(fix[i]);

      for (i=0; i<max_index(ver); i++)
        if ((ver[i] < fix[i]))
        {
          version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

          if (variant == "Plugin")
          {
            info += '  - Browser Plug-in (for Firefox) :\n';
          }
          else if (variant == "ActiveX")
          {
            info += '  - ActiveX control (for Internet Explorer) :\n';
          }
          info += '    ' + file + ', ' + version + '\n';

          if (variant == "ActiveX")
          {
            if (report_paranoia < 2)
              info += '\n' +
                      "  Moreover, its kill bit is not set so it is accessible via Internet" + '\n' +
                      "  Explorer." + '\n';
            else
              info += '\n' +
                      "  Note, though, that Nessus did not check whether the kill bit was" + '\n' +
                      "  set for the control's CLSID because of the Report Paranoia setting" + '\n' +
                      "  in effect when this scan was run." + '\n';
          }

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


# Issue a report.
if (info)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus found the following vulnerable instance(s) of SmartView Viewer\n",
      "on the remote host :\n",
      "\n",
      info
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
