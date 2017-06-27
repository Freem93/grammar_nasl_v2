#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23975);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/05/04 14:21:27 $");

  script_cve_id(
    "CVE-2007-0044",
    "CVE-2007-0045",
    "CVE-2007-0046",
    "CVE-2007-0047",
    "CVE-2007-0048"
  );
  script_bugtraq_id(21858);
  script_osvdb_id(31046, 31047, 31048, 31596, 34407);
  script_xref(name:"CERT", value:"815960");

  script_name(english:"Adobe PDF Plug-In < 8.0 / 7.0.9 / 6.0.6 Multiple Vulnerabilities (APSB07-01)");
  script_summary(english:"Checks version of nppdf32.dll");

  script_set_attribute(attribute:"synopsis", value:
"The browser plugin on the remote Windows host is affected by multiple
issues.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe PDF Plug-In installed on the remote host is
earlier than 8.0 / 7.0.9 / 6.0.6 and reportedly fails to properly
sanitize input to the 'FDF', 'XML', or 'XFDF' fields used by its 'Open
Parameters' feature. By tricking a user into accessing a specially
crafted link and depending on the browser with which the plugin is
used, a remote attacker may be able to leverage these issues to
conduct arbitrary code execution, denial of service, cross-site script
forgery, or cross-site scripting attacks against a user on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.wisec.it/vulns.php?page=9");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/455801/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/advisories/apsa07-01.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-01.html");
  script_set_attribute(attribute:"solution", value:
"Either disable displaying of PDF documents in web browsers or upgrade
to Adobe Reader / Acrobat 8.0 / 7.0.9 / 6.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(352);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl", "opera_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
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


# Determine possible installation paths.
paths = make_array();
# - Adobe itself.
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\AcroRd32.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value))
  {
    paths["Adobe"] = string(value[1], "Browser");
  }
  RegCloseKey(handle:key_h);
}
# - Internet Explorer.
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\IEXPLORE.EXE";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value))
  {
    path = ereg_replace(pattern:"^(.+);$", replace:"\1", string:value[1]);
    paths["Internet Explorer"] = string(path, "\\PLUGINS");
  }
  RegCloseKey(handle:key_h);
}
# - Firefox.
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value))
  {
    paths["Firefox"] = string(value[1], "plugins");
  }
  RegCloseKey(handle:key_h);
}
# - Opera
path = get_kb_item("SMB/Opera/Path");
if (!isnull(path))
{
  # nb: Opera seems to look in a variety of places for its plugins.
  paths["Opera1"] = string(path, "\\program\\plugins");
  if (paths["Firefox"]) paths["Opera2"] = paths["Firefox"];
  if (paths["Adobe"])   paths["Opera3"] = paths["Adobe"];
}
RegCloseKey(handle:hklm);


# Check the file version for each possible install path.
info = "";
found_opera_plugin = 0;
foreach browser (sort(keys(paths)))
{
  # Determine whether to check some browsers.
  if (
    (browser == "Adobe" && report_paranoia < 2) ||
    (browser =~ "Opera[23]" && found_opera_plugin == 1)
  ) check = 0;
  else check = 1;

  if (check)
  {
    # Determine its version from the executable itself.
    path = paths[browser];
    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
    dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\nppdf32.dll", string:path);
    NetUseDel(close:FALSE);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      exit(1);
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
      if ("Opera" >< browser) found_opera_plugin = 1;

      ver = GetFileVersion(handle:fh);
      CloseFile(handle:fh);

      # Check the version
      if (
        !isnull(ver) &&
        (
          ver[0] < 6 ||
          (ver[0] == 6 && ver[1] == 0 && ver[2] < 6) ||
          (ver[0] == 7 && ver[1] == 0 && ver[2] < 9)
        )
      )
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        if (browser == "Adobe")
          info += strcat(
            ' - Version ', version, ' of the plugin itself is located in\n',
            "   '", path, "'.", '\n'
          );
        else
        {
          if ("Opera" >< browser) browser = "Opera";
          info += strcat(
            ' - Version ', version, ' of the plugin is installed in ', browser, '\n',
            "   under '", path, "'.", '\n'
          );
        }
      }
    }
  }
}


if (info)
{
  security_hole(port:port, extra:info);
}


# Clean up.
NetUseDel();
