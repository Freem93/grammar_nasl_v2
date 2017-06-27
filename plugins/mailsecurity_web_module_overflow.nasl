#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20016);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2005-3182");
  script_bugtraq_id(15081);
  script_osvdb_id(19926);

  script_name(english:"GFI MailSecurity HTTP Management Interface Request Header Overflow");
  script_summary(english:"Checks for a buffer overflow vulnerability in GFI MailSecurity's Web Module");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of GFI MailSecurity on
the remote host suffers from a buffer overflow in its web-based
moderator interface. An unauthenticated attacker can reportedly
exploit this flaw by sending large strings in several areas of the
HTTP request to gain control of the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://online.securityfocus.com/archive/1/413142/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://kbase.gfi.com/showarticle.asp?id=KBID002451" );
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor advisory above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Open the key used for GFI MailSecurity.
#
# nb: this is for 8.x;
#     for 9.x, it's under "SOFTWARE\GFI\ContentSecurity\MailSecurity",
#              with keys "Build" and "Path" but not "ProductName".
key = "SOFTWARE\GFI FAX & VOICE\GFIAV";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"BUILD");
  if (!isnull(value)) build = value[1];

  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) path = value[1];

  value = RegQueryValue(handle:key_h, item:"ProductName");
  if (!isnull(value)) product = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# Check the versions of affected files if they're running a potentially vulnerable build.
if (
  !isnull(product) && !isnull(build) && !isnull(path) &&
  "GFI MailSecurity for Exchange/SMTP" >< product &&
  # nb: "20040723" => version 8.1.
  build =~ "^200[0-4]"
)
{
  NetUseDel(close:FALSE);

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1) {
    NetUseDel();
    exit(1);
  }
  path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:path);

  # File versions from patched files..
  pvers["Convertor.dll"] = "1.0.0.10";
  pvers["GFIQuarantine.dll"] = "1.0.0.85";
  pvers["gfiweb.dll"] = "1.0.125.127";
  pvers["vsapiusr.dll"] = "1.0.0.23";

  foreach file (keys(pvers)) {
    fh = CreateFile(
      file:string(path, "\\", file),
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);

      if (!isnull(ver))
      {
        pver = split(pvers[file], sep:".", keep:0);
        if (
          # nb: file versions from 8.1 BUILD 20040723 are:
          #     8004.114.0.8 (Convertor.dll)
          #     8003.1215.0.85 (GFIQuarantine.dll)
          #     8014.426.125.127 (gfiweb.dll)
          #     8004.119.0.21 (vsapiusr.dll)
          (ver[0] > 8000) ||
          # nb: in case earlier patches followed the newer versioning scheme.
          (ver[0]  < pver[0]) ||
          (ver[0] == pver[0] && ver[1]  < pver[1]) ||
          (ver[0] == pver[0] && ver[1] == pver[1] && ver[2]  < pver[2]) ||
          (ver[0] == pver[0] && ver[1] == pver[1] && ver[2] == pver[2] && ver[3] < pver[3])
        )
        {
          security_hole(port);
          break;
        }
      }
    }
  }
}
NetUseDel();
