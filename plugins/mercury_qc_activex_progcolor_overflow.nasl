#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24909);
  script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_cve_id("CVE-2007-1819");
  script_bugtraq_id(23239);
  script_osvdb_id(34317);

  script_name(english:"TestDirector (TD) for Mercury Quality Center SPIDERLib.Loader ActiveX Control (Spider90.ocx) ProgColor Property Overflow");
  script_summary(english:"Checks version of Quality Center's ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is susceptible to
a buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The Windows remote host contains an ActiveX control used by Mercury
Quality Center, a web-based solution for automatic software testing.

The version of this ActiveX control on the remote host reportedly
contains a buffer overflow vulnerability in its 'ProgColor' property.
By setting the property to an overly long value, a remote attacker may
be able to leverage this issue to execute arbitrary code on the remote
host subject to the privileges of the current user.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa0d77e4");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Apr/66" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee538bf9" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/12180" );
 script_set_attribute(attribute:"solution", value:
"Either remove the control if Quality Center access is not needed or
apply the appropriate patch referenced in the vendor advisory above to
the Quality Control server and browse the Quality Control server's
Site Administration page to update the control on the remote host.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'HP Mercury Quality Center ActiveX Control ProgColor Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/02");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/04/02");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/03");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");


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


# Check whether it's installed.
file = NULL;
flags = NULL;
ver = NULL;

clsids = make_list(
  # Quality Center 9.0.
  '{98C53984-8BF8-4D11-9B1C-C324FCA9CADE}',
  # Quality Center 8.2 SP1.
  '{205e7068-6d03-4566-ad06-a146b592fba5}'
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
  if (file) break;
}
if (file)
{
  # Check its version.
  key = "SOFTWARE\Microsoft\Code Store Database\Distribution Units\" + clsid +  "\InstalledVersion";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) ver = value[1];

    RegCloseKey(handle:key_h);
  }
}
if (report_paranoia < 2 && file)
{
  # Check the compatibility flags for the control.
  key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid +  "";
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
ocx =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
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
  CloseFile(handle:fh);

  # Check the version number.
  iver = split(ver, sep:',', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  if (
    !isnull(ver) &&
    (
      iver[0] < 9 ||
      (
        iver[0] == 9 &&
        (
          (
            "Spider80.ocx" >< file &&
            iver[1] == 0 && iver[2] == 0 && iver[3] < 3660
          ) ||
          (
            "Spider90.ocx" >< file &&
            iver[1] == 1 && iver[2] == 0 && iver[3] < 4382
          )
        )
      )
    )
  )
  {
    version = string(iver[0], ".", iver[1], ".", iver[2], ".", iver[3]);

    # There's a problem if the kill bit isn't set.
    report = NULL;
    if (isnull(flags) || flags != 0x400)
      report = string(
        "Version ", version, " of the control is installed as \n",
        "\n",
        "  ", file, "\n"
      );
    # Or we're just being paranoid.
    else if (report_paranoia > 1)
      report = string(
        "Version ", version, " of the control is installed as \n",
        "\n",
        "  ", file, "\n",
        "\n",
        "Note that the control may have its kill bit set, but the issue\n",
        "is being flagged because of the setting of Report Paranoia in\n",
        "effect when the scan was run.\n"
      );

    if (report) security_hole(port:port, extra:report);
  }
}


# Clean up.
NetUseDel();
