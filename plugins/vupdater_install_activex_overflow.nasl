#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(21336);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2017/02/21 14:37:43 $");

  script_cve_id("CVE-2006-2273");
  script_bugtraq_id(17939);
  script_osvdb_id(25431);

  script_name(english:"I-Nav VUpdater.Install ActiveX Buffer Overflow");
  script_summary(english:"Checks version of I-Nav ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host contains an ActiveX control, 'VUpdater.Install',
associated with Verisign I-Nav, which provides support for
Internationalized Domain Names in Microsoft Internet Explorer, Outlook
and Outlook Express that reportedly contains a buffer overflow
vulnerability that arises when processing CAB files. A remote attacker
may be able to leverage this issue to specify an arbitrary executable
to be run subject to the privileges of the current user.");
 script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-014.html");
 script_set_attribute(attribute:"see_also", value:"http://www.idnnow.com/" );
 script_set_attribute(attribute:"solution", value:"Download the latest version of the software from the vendor.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/05/11");

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


# Determine if the control is installed.
clid = "B562BC94-9A3A-4760-AE48-0D52FD01B1B5";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) name = value[1];
  else name = NULL;

  RegCloseKey(handle:key_h);
}
else name = NULL;


# If it is, get its location.
if (name && "VeriSign Software Update Service" >< name)
{
  # Determine where it's installed.
  key = "SOFTWARE\Classes\CLSID\{" + clid + "}\InprocServer32";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) file = value[1];
    else file = NULL;

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);


# If the location's available...
if (file )
{
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

  # There's a problem if the version number is < 2.0.2.0.
  if (
    !isnull(ver) &&
    (
      int(ver[0]) < 2 ||
      (int(ver[0]) == 2 && int(ver[1]) == 0 && int(ver[2]) < 2)
    )
  )
  {
    if (report_verbosity > 1)
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "Version ", version, " of the control is installed as \n",
        "\n",
        "  ", file, "\n"
      );
    }
    else report = NULL;

    security_hole(port:port, extra:report);
  }
}


# Clean up.
NetUseDel();
