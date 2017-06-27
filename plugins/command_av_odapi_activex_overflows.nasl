#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25369);
  script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2007-2917");
  script_bugtraq_id(24255);
  script_osvdb_id(36801);
  script_xref(name:"CERT", value:"563401");

  script_name(english:"Command Antivirus odapi.dll ActiveX Control Multiple Overflows");
  script_summary(english:"Checks for Command Antivirus ActiveX control");


 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is susceptible to
multiple buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The Windows remote host contains an ActiveX control from Authentium's
Command Antivirus or a third-party antivirus product that is based on
it.

The version of this ActiveX control on the remote host reportedly
contains multiple buffer overflow vulnerabilities. A remote attacker
may be able to leverage these issues to execute arbitrary code on the
remote host subject to the privileges of the current user.");
 script_set_attribute(attribute:"solution", value:
"Contact the software vendor for updates or disable the use of this
ActiveX control from within Internet Explorer by setting the kill bits
for the associated CLSIDs.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/02");

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

#

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


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

clsids = make_list(
  "{103CAE29-DB09-4F77-812B-FFC0C3BC91A1}",
  "{1F22F6F1-FDC5-4C6D-9335-B6E31315FB1B}",
  "{253A6409-6917-48EF-9CC7-9CB79FDA4169}",
  "{50F3C8D1-E5E8-463D-A6E5-5A5966359538}",
  "{567408B9-78B1-44DD-9CC2-7AC136C916C5}",
  "{67EC8D27-C3CD-447E-9315-46A04DDB6C35}",
  "{6D855303-A902-4608-8668-C177F80AB429}",
  "{8EDDD996-E47F-4C59-8505-9FC570612FB6}",
  "{A1962F85-324C-4751-83ED-27426F9F6E36}",
  "{FED9DA10-9C9E-4AEB-B5B2-51C7ADC7A4DA}"
);
foreach clsid (clsids)
{
  key = "SOFTWARE\Classes\CLSID\" + clsid +  "\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) file = value[1];

    RegCloseKey(handle:key_h);
  }
  if (!isnull(file)) break;
}

# If it is...
if (file)
{
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

  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    # If the file version is under 4.93.8...
    if (
      !isnull(ver) &&
      (
        ver[0] < 4 ||
        (
          ver[0] == 4 &&
          (
            ver[1] < 93 ||
            (ver[1] == 93 && ver[2] < 8)
          )
        )
      )
    )
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

      report = NULL;
      if (report_paranoia > 1)
        report = string(
          "According to the registry, version ", version, " of the vulnerable control\n",
          "is installed as :\n",
          "\n",
          "  ", file, "\n",
          "\n",
          "Note, though, that Nessus did not check whether the kill bits were\n",
          "set for the control's various CLSIDs because of the Report Paranoia\n",
          "setting in effect when this scan was run.\n"
        );
      else
      {
        info = NULL;

        # Check the compatibility flags for the control.
        foreach clsid (clsids)
        {
          key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{" + clsid +  "}";
          key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
          flags = NULL;
          if (!isnull(key_h))
          {
            value = RegQueryValue(handle:key_h, item:"Compatibility Flags");
            if (!isnull(value)) flags = value[1];

            RegCloseKey(handle:key_h);
          }

          # There's a problem if the kill bit isn't set.
          if (isnull(flags) || flags != 0x400) info += '    ' + clsid + '\n';
        }

        if (info)
          report = string(
            "According to the registry, version ", version, " of the vulnerable control\n",
            "is installed as :\n",
            "\n",
            "  ", file, "\n",
            "\n",
            "and accessible via Internet Explorer using the following CLSID(s) :\n",
            "\n",
            info
          );
      }

      if (report)
        security_hole(port:port, extra:report);
    }
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
