#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(41945);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/05/20 14:02:59 $");

  script_cve_id("CVE-2009-0301");
  script_bugtraq_id(33453);
  script_osvdb_id(51590);
  script_xref(name:"EDB-ID", value:"7868");

  script_name(english:"FlexCell Grid FlexCell.Grid ActiveX Control Multiple Method Arbitrary File Overwrite");
  script_summary(english:"Checks version of control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows overwriting
arbitrary files.");
  script_set_attribute(attribute:"description", value:
"The remote host contains the FlexCell.Grid ActiveX control, a
component of the FlexCell grid control software.

The version of the control installed on the remote host reportedly
fails to validate input to the 'File' argument of the 'SaveFile' and
'ExportToXML' methods before writing to the specified filename.

If an attacker can trick a user on the affected host into viewing a
specially crafted HTML document, this issue could be leveraged to
create or overwrite arbitrary files on the affected system subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.grid2000.com/news.html#activex");
  script_set_attribute(attribute:"solution", value:"Upgrade to FlexCell Grid Control 5.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(1, "Port "+port+" is closed.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Can't open socket on TCP port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}


# Find the CLSID.
clsid = NULL;

key = "SOFTWARE\Classes\FlexCell.Grid\CLSID";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) clsid = item[1];

  RegCloseKey(handle:key_h);
}
if (isnull(clsid))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0, "The FlexCell.Grid control is not installed.");
}


# Now locate the file used by the control.
file = NULL;
flags = NULL;

key = "SOFTWARE\Classes\CLSID\" + clsid +  "\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) file = item[1];

  RegCloseKey(handle:key_h);
}
if (report_paranoia < 2 && file)
{
  # Check the compatibility flags for the control.
  key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid;
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Compatibility Flags");
    if (!isnull(item)) flags = item[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(file))
{
  NetUseDel();
  exit(1, "Can't identify the file associated with CLSID '"+clsid+"'.");
}


# Check the version of the control.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
ocx =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to '"+share+"' share.");
}

fh = CreateFile(
  file:ocx,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

if (isnull(ver))
{
  exit(1, "Can't get file version of '"+file+"'.");
}


# Rewrite version info to make it agree with what the vendor / installer report.
version = string(ver[0], ".", ver[1], ".", ver[3]);
ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);


fixed_version = "5.8.0";
report = "";

fix = split(fixed_version, sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(ver); i++)
{
  if ((ver[i] < fix[i]))
  {

    if (report_paranoia > 1)
        report = string(
          "\n",
          "  Class Identifier  : ", clsid, "\n",
          "  Filename          : ", file, "\n",
          "  Installed Version : ", version, "\n",
          "  Fixed Version     : ", fixed_version, "\n",
          "\n",
          "Note, though, that Nessus did not check whether the kill bit was\n",
          "set for the control's CLSID because of the Report Paranoia setting\n",
          "in effect when this scan was run.\n"
        );
      else if (isnull(flags) || ((flags & 0x400) != 0x400))
        report = string(
          "\n",
          "  Class Identifier  : ", clsid, "\n",
          "  Filename          : ", file, "\n",
          "  Installed Version : ", version, "\n",
          "  Fixed Version     : ", fixed_version, "\n",
          "\n",
          "Moreover, its kill bit is not set so it is accessible via Internet\n",
          "Explorer.\n"
        );
    if (report)
    {
      if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
      else security_hole(kb_smb_transport());
      exit(0);
    }
    else
    {
      if (!isnull(flags) && ((flags & 0x400) == 0x400)) exit(0, "The kill bit is set for CLSID '"+clsid+"'.");
      else exit(1, "Can't determine if the kill bit is set for CLSID '"+clsid+"'.");
    }
  }
  else if (ver[i] > fix[i])
    break;
}
exit(0, "The host is not affected since FlexCell Grid Control "+version+" is installed.");
