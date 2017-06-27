#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(35743);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id("CVE-2009-0505");
  script_bugtraq_id(33883);
  script_osvdb_id(56370);

  script_name(english:"IBM TXSeries for Multiplatforms CICS Listener Crafted CICSAS eci Response Timeout DoS");
  script_summary(english:"Checks version of libcicsco.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM TXSeries installed on the remote host reportedly
waits for a 'forcepurge' acknowledgement from a CICS Application
Server after an 'eci' response timeout. A remote, authenticated
attacker may be able to leverage this issue to cause a denial of
service or have some other unspecified impact.");

  script_set_attribute(attribute:"solution", value:"Apply the recommended Interim Fix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


function display_dword (dword, nox)
{
 local_var tmp;

 if (isnull(nox) || (nox == FALSE))
   tmp = "0x";
 else
   tmp = "";

 return string (tmp,
               toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) & 0xFF,
                               (dword >>> 16) & 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                        )
                      )
               );
}


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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


# Find the install path.
path = NULL;

key = "SOFTWARE\IBM\TXSeries-CICS\CurrentVersion";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Grab the version from libcicsco.dll
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\libcicsco.dll", string:path);
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

version = NULL;
if (!isnull(fh))
{
  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];
  if (!isnull(children))
  {
    varfileinfo = children['VarFileInfo'];
    if (!isnull(varfileinfo))
    {
      translation =
        (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
        get_word (blob:varfileinfo['Translation'], pos:2);
      translation = tolower(display_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[translation];
      if (!isnull(data)) version = data['FileVersion'];
      else
      {
        data = stringfileinfo[toupper(translation)];
        if (!isnull(data)) version = data['FileVersion'];
      }
    }
  }

  CloseFile(handle:fh);
}
NetUseDel();


# Check for affected versions.
if (
  !isnull(version) &&
  "TXSeries " >< version &&
  (
    version =~ "^TXSeries ([0-5]\.|6\.[01]\.)" ||
    # nb: FileVersion for fix is "TXSeries 6.2.0.0 Interim Service Fix 7 s620-L080611"
    version =~ "^TXSeries 6\.2\.0\.0 .+-L0([0-7]|80([1-5]|6(0[0-9]|10)))"
  )
)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      path, "\\bin\\libcicsco.dll has not been patched :\n",
      "\n",
      "  Actual FileVersion   : ", version, "\n",
      "  Expected FileVersion : TXSeries 6.2.0.0 Interim Service Fix 7 s620-L080611\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
