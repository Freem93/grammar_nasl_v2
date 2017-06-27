#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33476);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/02 14:37:09 $");

  script_cve_id("CVE-2008-2991");
  script_bugtraq_id(30137);
  script_osvdb_id(46867, 51452);
  script_xref(name:"Secunia", value:"31001");

  script_name(english:"RoboHelp Server Help Errors Multiple Vulnerabilities (APSB08-16)");
  script_summary(english:"Checks for patched files");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installation of Adobe RoboHelp Server on the remote host is
version 7.00 or older and does not contain the APSB08-16 update file.
As a result, it is probably affected by a SQL injection and a
cross-site scripting vulnerability. The SQL injection issue reportedly
can be exploited to manipulate queries against the RoboHelp back-end
database either by an authenticated attacker who sends a specially
crafted HTTP request to the server or by an unauthenticated attacker
who tricks an authenticated user into clicking on a malicious link.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Jul/93");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb08-16.html");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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


# Make sure it's installed.
path = NULL;

key = "SOFTWARE\Adobe\RoboHelp Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9]+\.")
    {
      key2 = key + "\" + subkey + "\System";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        item = RegQueryValue(handle:key2_h, item:"InstallPath");
        if (!isnull(item))
        {
          path = item[1];
          path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
        }
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version of Robo.dll.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\Robo.dll", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}


# If it's an affected version...
if (
  !isnull(ver) &&
  (
    ver[0] < 7 ||
    (ver[0] == 7 && ver[1] == 0)
  )
)
{
  # Check if each affected file has been patched.
  files = make_list(
    "Report_API.asp",
    "Report_Template.asp",
    "SQL_Lib.asp"
  );

  vuln = FALSE;
  foreach file (files)
  {
    asp = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Reports\"+file, string:path);
    NetUseDel(close:FALSE);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
    if (rc != 1)
    {
      NetUseDel();
      break;
    }

    fh = CreateFile(
      file:asp,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      # Read an initial chunk.
      chunk = 35000;
      size = GetFileSize(handle:fh);
      if (size > 0)
      {
        if (chunk > size) chunk = size;
        data = ReadFile(handle:fh, length:chunk, offset:0);

        if (data)
        {
          if (
            file == 'Report_API.asp' &&
            'function escapeForSQL' >!< data
          ) vuln = TRUE;
          else if (
            file == 'Report_Template.asp' &&
            'function escapeForXSS' >!< data
          ) vuln = TRUE;
          else if (
            file == 'SQL_Lib.asp' &&
            'sql += parseInt(r) + "" ;' >!< data
          ) vuln = TRUE;
        }
      }
      CloseFile(handle:fh);

      if (vuln) break;
    }
  }
}
NetUseDel();


# Report if an issue was found.
if (vuln)
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

