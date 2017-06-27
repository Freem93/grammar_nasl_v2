#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24814);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2007-1498");
  script_bugtraq_id(22952);
  script_osvdb_id(33796);

  script_name(english:"ePolicy Orchestrator SiteManager ActiveX Control Multiple Buffer Overflows");
  script_summary(english:"Checks version of SiteManager ActiveX control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the SiteManager ActiveX control included with McAfee
ePolicy Orchestrator or ProtectionPilot and installed on the remote
host reportedly contains several buffer overflows. If an attacker can
trick a user on the affected host into visiting a specially crafted
web page, this issue could be leveraged to execute arbitrary code on
the host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Mar/224");
  script_set_attribute(attribute:"see_also", value:"https://knowledge.mcafee.com/article/25/612495_f.SAL_Public.html");
  script_set_attribute(attribute:"see_also", value:"https://knowledge.mcafee.com/article/26/612496_f.SAL_Public.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch as described in the vendor advisories
referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


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


# This function returns TRUE if the version string ver lies in
# the range [low, high].
function ver_inrange(ver, low, high) {
  local_var ver_parts, low_parts, high_parts, i, p, low_p, high_p;

  if (isnull(ver) || isnull(low) || isnull(high)) return FALSE;

  # Split levels into parts.
  ver_parts = split(ver, sep:".", keep:0);
  low_parts = split(low, sep:".", keep:0);
  high_parts = split(high, sep:".", keep:0);

  # Compare each part.
  i = 0;
  while (ver_parts[i] != NULL) {
    p = int(ver_parts[i]);
    low_p = int(low_parts[i]);
    if (low_p == NULL) low_p = 0;
    high_p = int(high_parts[i]);
    if (high_p == NULL) high_p = 0;

    if (p > low_p && p < high_p) return TRUE;
    if (p < low_p || p > high_p) return FALSE;
    ++i;
  }
  return TRUE;
}


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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
clsid = '{4124FDF6-B540-44C5-96B4-A380CEE9826A}';
file = NULL;
key = "SOFTWARE\Classes\CLSID\" + clsid +  "\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) file = value[1];

  RegCloseKey(handle:key_h);
}
if (isnull(file))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Figure out location of the product install.
prod_path = NULL;
key = "SOFTWARE\Network Associates\ePolicy Orchestrator";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallFolder");
  if (!isnull(value)) prod_path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(prod_path))
{
  NetUseDel();
  exit(0);
}


# Determine the version of the product itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:prod_path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\NetBrwsr.dll", string:prod_path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

prod = NULL;
prod_ver = NULL;
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

  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];
  if (!isnull(children))
  {
    varfileinfo = children['VarFileInfo'];
    if (!isnull(varfileinfo))
    {
      translation =
        (get_word(blob:varfileinfo['Translation'], pos:0) << 16) +
        get_word(blob:varfileinfo['Translation'], pos:2);
      translation = tolower(display_dword(dword:translation, nox:TRUE));
    }
    stringfileinfo = children['StringFileInfo'];
    if (!isnull(stringfileinfo) && !isnull(translation))
    {
      data = stringfileinfo[translation];
      if (!isnull(data)) prod = data['ProductName'];
    }
  }

  CloseFile(handle:fh);
}
if (isnull(ver))
{
  NetUseDel();
  exit(0);
}
prod = prod - "McAfee ";
prod_ver = string(ver[0], ".", ver[1], ".", ver[2]);


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

  # Check the file version of the control.
  version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
  if (
    !isnull(ver) &&
    (
      # nb: high is specified here as the upper limit of affected versions rather than
      #     the fixed version that apppears in McAfee's advisories.
      (
        "ePolicy Orchestrator" == prod &&
        (
          (prod_ver == "3.6.1" && ver_inrange(ver:version, low:"0.0.0.0", high:"3.6.1.201")) ||
          (prod_ver == "3.6.0" && ver_inrange(ver:version, low:"0.0.0.0", high:"3.6.0.618")) ||
          (prod_ver == "3.5.0" && ver_inrange(ver:version, low:"0.0.0.0", high:"1.5.0.522"))
        )
      ) ||
      (
        "ProtectionPilot" == prod &&
        (
          (prod_ver == "1.5.0" && ver_inrange(ver:version, low:"0.0.0.0", high:"1.5.0.528")) ||
          (prod_ver == "1.1.1" && ver_inrange(ver:version, low:"0.0.0.0", high:"1.5.0.525"))
        )
      )
    )
  )
  {
    report = string(
      "Version ", version, " of the control from ", prod, " ", prod_ver, "\n",
      "is installed as :\n",
      "\n",
      "  ", file, "\n"
    );
    security_hole(port:port, extra:report);
  }
}


# Clean up.
NetUseDel();
