#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24912);
  script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_cve_id("CVE-2007-1684");
  script_bugtraq_id(23290);
  script_osvdb_id(34320);
  script_xref(name:"CERT", value:"556801");

  script_name(english:"SolidWorks Sldimdownload ActiveX Control Arbitrary Code Execution");
  script_summary(english:"Checks version of Sldimdownload ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows execution
of arbitrary code.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the 'sldimdownload' ActiveX
control included with SolidWorks' 3D CAD software.

The version of this ActiveX control on the remote host fails to
sanitize input to the 'installerpath' and 'applicationarguments'
parameters of the 'Run' method. If an attacker can trick a user on the
affected host into visiting a specially crafted web page, he can
leverage this issue to execute arbitrary code on the host subject to
the user's privileges.");
 script_set_attribute(attribute:"solution", value:"Update to version 16.0.0.6 or later of the control.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/04");

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
file = NULL;
flags = NULL;

clsid = '{AB6633A8-60A9-4F5D-B66C-ABE268CC3227}';
key = "SOFTWARE\Classes\CLSID\" + clsid +  "\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) file = value[1];

  RegCloseKey(handle:key_h);
}
if (report_paranoia < 2 && file)
{
  # Check the compatibility flags for the control.
  key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid + "";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Compatibility Flags");
    if (!isnull(value)) flags = value[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(file))
{
  NetUseDel();
  exit(0);
}


# Determine the version from the control itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:dll,
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


# Check the version number.
if (!isnull(ver))
{
  fix = split("16.0.0.6", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = NULL;

      if (report_paranoia > 1)
        report = string(
          "Version ", version, " of the control is installed as :\n",
          "\n",
          "  ", file, "\n",
          "\n",
          "Nessus did not check, though, whether it is disabled in Internet\n",
          "Explorer because of the Report Paranoia setting in effect when\n",
          "this scan was run.\n"
        );
      else
      {
        # There's a problem if the kill bit isn't set.
        if (isnull(flags) || flags != 0x400)
        {
          report = string(
            "Version ", version, " of the control is installed as :\n",
            "\n",
            "  ", file, "\n"
          );
        }
      }
      if (report) security_hole(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
