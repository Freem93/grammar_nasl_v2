#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23648);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/02 20:50:26 $");

  script_cve_id("CVE-2006-3890", "CVE-2006-5198");
  script_bugtraq_id(21060, 21108);
  script_osvdb_id(30432, 30433);
  script_xref(name:"CERT", value:"225217");

  script_name(english:"WinZip FileView ActiveX Control Vulnerabilities");
  script_summary(english:"Checks version of FileView ActiveX control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
arbitrary code execution and buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of the 'FileView' ActiveX control
from Sky Software that is included in third-party products such as
WinZip.

The version of this ActiveX control on the remote host reportedly
exposes several methods that either can be used to execute arbitrary
code or are affected by buffer overflow vulnerabilities. If an
attacker can trick a user on the affected host into visiting a
specially crafted web page, he can leverage these issues to execute
arbitrary code on the host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-040.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Nov/245");
  script_set_attribute(attribute:"see_also", value:"http://www.winzip.com/wz7245.htm");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 6.1.7242.0 or later of the control or WinZip 10
build 7245 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WinZip FileView (WZFILEVIEW.FileViewCtrl.61) ActiveX Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winzip:winzip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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
controls = make_array();
flags = make_array();

#
# strcat() due to Bug#1725
#
clsids = make_list(
  strcat("0A7A7240", "-D038", "-DB9F", "-B3B1", "-7FEFFE5F9ED6"),
  strcat("247D857F", "-1034", "-4AA6", "-BB1A", "-347D1A3340C8"),
  strcat("551E5AC9", "-BDBD", "-48EC", "-8AE2", "-ECAF90C7A214"),
  strcat("A09AE68F", "-B14D", "-43ED", "-B713", "-BA413F034904")
);
foreach clsid (clsids)
{
  key = "SOFTWARE\Classes\CLSID\{" + clsid +  "}\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) controls[clsid] = value[1];

    RegCloseKey(handle:key_h);
  }
  if (report_paranoia < 2)
  {
    # Check the compatibility flags for the control.
    key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{" + clsid +  "}";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    flags = NULL;
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"Compatibility Flags");
      if (!isnull(value)) flags[clsid] = value[1];

      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);
if (max_index(keys(controls)) == 0) {
  NetUseDel();
  exit(0);
}


foreach clsid (keys(controls))
{
  # Determine the version from the control itself.
  file = controls[clsid];
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  ocx =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:ocx,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # Check the version number.
  if (
    !isnull(ver) &&
    (
      ver[0] < 6 ||
      (
        ver[0] == 6 &&
        (
          ver[1] < 1 ||
          (ver[1] == 1 && ver[2] < 7242)
        )
      )
    )
  )
  {
    report = NULL; found = 0;
    if (report_paranoia > 1)
      report = string(
        "The ActiveX control is installed, but Nessus did not check\n",
        "whether it is disabled in Internet Explorer because of the\n",
        "Report Paranoia setting in effect when this scan was run.\n"
      );
    else
    {
      # There's a problem if the kill bit isn't set.
      if (isnull(flags[clsid]) || flags[clsid] != 0x400)
      {
        if (report_verbosity)
        {
          version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
          report = string(
            "Version ", version, " of the control is installed as \n",
            "\n",
            "  ", file, "\n"
          );
        }
        else found = 1;
      }
    }
    if (report || found)
        security_hole(port:port, extra: report);
  }
}


# Clean up.
NetUseDel();
