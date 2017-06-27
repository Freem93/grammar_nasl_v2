#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21772);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2017/05/08 18:22:10 $");

  script_cve_id("CVE-2006-3134", "CVE-2006-6442");
  script_bugtraq_id(18678);
  script_osvdb_id(26874);

  script_name(english:"Gracenote CDDBControl ActiveX Control Option String Overflow");
  script_summary(english:"Checks for the CDDBControl ActiveX control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is susceptible to
a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Windows remote host contains the Gracenote CDDBControl ActiveX
control, which is used by various products, including AOL's software,
to lookup CD information in the Gracenote CDDB and is commonly marked
as safe for scripting.

The version of this ActiveX control on the remote host reportedly
contains a buffer overflow vulnerability that arises when a large
string is supplied as an option for the control. A remote attacker may
be able to leverage this issue to execute arbitrary code on the remote
host subject to the privileges of the current user.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-019.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jun/883" );
  # https://web.archive.org/web/20060721103915/http://www.gracenote.com/corporate/security/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?67486937");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2006-69/advisory/" );
  script_set_attribute(attribute:"solution", value:
"Contact the developer of the software you are using for a patch or new
version; otherwise, use Gracenote's tool to set its kill bit to
disable the control in Internet Explorer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

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
clid = "F4BAFF02-F907-11D2-8F8F-00C04F4C3B9F";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
file = NULL;
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) file = value[1];

  RegCloseKey(handle:key_h);
}


# If it is...
if (file)
{
  # Get the compatibility flags for the control.
  key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\{" + clid +  "}";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  flags = NULL;
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Compatibility Flags");
    if (!isnull(value)) flags = value[1];

    RegCloseKey(handle:key_h);
  }

  # Determine the version from the DLL itself.
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
  }

  # Check the version number.
  if (
    !isnull(ver) &&
    (
      ver[0] == 2 &&
      (
        # 2.1.0.10 is affected.
        (ver[1] == 1 && ver[2] == 0 && ver[3] == 10) ||
        # 2.2.x.x are affected.
        (ver[1] == 2) ||
        # 2.3.x.x are affected.
        (ver[1] == 3) ||
        # 2.4.0.[0-8] are affected.
        (ver[1] == 4 && ver[2] == 0 && (ver[3] >= 0 && ver[3] <= 8)) ||
        # 2.5.0.[1-4] are affected.
        (ver[1] == 5 && ver[2] == 0 && (ver[3] >= 1 && ver[3] <= 4))
      )
    )
  )
  {
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

    if ( file ) set_kb_item (name:"GraceNote/CDDBControl/File", value:file);
    if ( version ) set_kb_item (name:"GraceNote/CDDBControl/Version", value:version);
    if ( flags ) set_kb_item (name:"GraceNote/CDDBControl/Flags", value:flags);

    # There's a problem if the kill bit isn't set.
    report = NULL;
    if (isnull(flags) || flags != 0x400)
      report = string(
        "\n",
        "Version ", version, " of the control is installed as \n",
        "\n",
        "  ", file, "\n"
      );
    # Or we're just being paranoid.
    else if (report_paranoia > 1)
      report = string(
        "\n",
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
RegCloseKey(handle:hklm);
NetUseDel();
