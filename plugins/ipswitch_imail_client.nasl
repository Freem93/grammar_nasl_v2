#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27590);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2007-4345");
  script_bugtraq_id(26252);
  script_osvdb_id(39389);

  script_name(english:"Ipswitch IMail Client Multipart MIME Email Message Handling Overflow");
  script_summary(english:"Checks version of IMail Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a program that is prone to a buffer
overflow attack.");
  script_set_attribute(attribute:"description", value:
"IMail Client, a tool for administering Ipswitch IMail Server, is
installed on the remote Windows host.

The version of IMail Client on the remote host contains a boundary
error that can be triggered by a long 'boundary' parameter when
processing emails with multipart MIME data. If an attacker can trick
the Ipswitch Mail Server administrator to open a specially crafted
email using the affected application, he can leverage this issue to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-81/advisory/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482988");
  script_set_attribute(attribute:"solution", value:"Delete the IMail Client application.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:imail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(0);


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Determine where it's installed.
path = NULL;

key = "SOFTWARE\Ipswitch\IMail\Global";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"TopDir");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Determine the version of the IMail Client.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\IMail.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0);
}
ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();
if (isnull(ver)) exit(0);


# If it's an affected version...
if (report_paranoia > 1)
{
  report = string(
    "Note that Nessus did not check the version of the IMail Client installed\n",
    "on the remote host because of the Report Paranoia setting in effect when\n",
    "this scan was run.\n"
  );
  security_hole(port:port, extra:report);
}
else if (
  ver[0] < 7 ||
  (
    ver[0] == 7 &&
    (
      ver[1] < 10 ||
      (
        ver[1] == 10 &&
        (
          ver[2] < 5 ||
          (ver[2] == 5 && ver[3] == 0)
        )
      )
    )
  )
)
{
  version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
  report = string(
    "Version ", version, " of the IMail Client is installed on the remote host under :\n",
    "\n",
    "  ", path, "\n"
  );
  security_hole(port:port, extra:report);
}

