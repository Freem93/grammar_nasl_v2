#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51812);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/22 15:29:15 $");

  script_cve_id("CVE-2011-0272");
  script_bugtraq_id(45792);
  script_osvdb_id(70432);
  script_xref(name:"Secunia", value:"42898");

  script_name(english:"HP LoadRunner Unspecified Arbitrary Remote Code Execution");
  script_summary(english:"Checks version in registry and for presence of a workaround");

  script_set_attribute(attribute:"synopsis", value:
"The version of HP LoadRunner installed on the remote host contains a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote host reportedly
blindly trusts user-supplied data as an allocation size and uses to
copy data from a request packet into a statically allocated heap
buffer.

A remote attacker who is able to contact TCP ports 5001 or 5002 on the
remote host can exploit this issue to execute arbitrary code with
SYSTEM privileges.");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to HP LoadRunner 10.0 or close ports 5001 and 5002 as
described in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-015/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Jan/317");
   # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c02680678
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e11838f0");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Jan/81");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");


function ini_parse(blob)
{
  local_var ini, line, lines, match, section;

  if (isnull(blob) || strlen(blob) == 0) return NULL;

  section = "";
  ini = make_array();

  lines = split(blob, sep:'\r\n');
  foreach line (lines)
  {
    line = chomp(line);

    # Ignore comments.
    if (line =~ "^\s*;") continue;

    # Track which section we're in.
    match = eregmatch(string:line, pattern:"^\s*\[\s*([^\]]+?)\s*\]");
    if (!isnull(match))
    {
      section = match[1] + ".";
      continue;
    }

    # Parse quoted variable.
    match = eregmatch(string:line, pattern:'^\\s*([^=]+?)\\s*=\\s*"([^"]*)"');
    if (!isnull(match))
    {
      ini[section + match[1]] = match[2];
      continue;
    }

    # Parse unquoted variable.
    match = eregmatch(string:line, pattern:"^\s*([^=]+?)\s*=\s*([^;]*?)\s*(;.*)?\s*$");
    if (!isnull(match))
    {
      ini[section + match[1]] = match[2];
      continue;
    }
  }

  return ini;
}

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.


# Try to connect to IPC$ share.
if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

# Get a handle into the registry for most of the data we need.
full_path = NULL;
installed = FALSE;
major = NULL;
minor = NULL;

handle = RegOpenKey(
  handle : hklm,
  key    : "SOFTWARE\Mercury Interactive\LoadRunner\CurrentVersion",
  mode   : MAXIMUM_ALLOWED
);
if (!isnull(handle))
{
  installed = TRUE;

  item = RegQueryValue(handle:handle, item:"Major");
  if (!isnull(item)) major = item[1];

  item = RegQueryValue(handle:handle, item:"Minor");
  if (!isnull(item)) minor = item[1];

  item = RegQueryValue(handle:handle, item:"LoadRunner");
  if (!isnull(item)) full_path = item[1];

  RegCloseKey(handle:handle);
}
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Examine retrieved keys to see if software is an affected version.
if (!installed)
{
  NetUseDel();
  exit(0, "LoadRunner does not appear to be installed.");
}
if (isnull(major) || isnull(minor) || isnull(full_path))
{
  NetUseDel();
  exit(1, "Can't find necessary registry keys.");
}
if (major != 9 || minor != 52)
{
  NetUseDel();
  exit(0, "LoadRunner version "+major+"."+minor+" is installed and thus not affected.");
}

# Parse out the share and the path.
full_path += "\launch_service\dat\merc_agent.cfg";
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:full_path);
path = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:full_path);

# Connect to share.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to " + share + " share.");
}

# Open config file.
file_found = FALSE;
workaround = FALSE;

fh = CreateFile(
  file               : path,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
);
if (!isnull(fh))
{
  contents = "";
  file_found = TRUE;

  # The file exists, so we need to check it for the workaround.
  length = GetFileSize(handle:fh);
  if (length > 0)
  {
    bytes_read = 0;
    for (offset = 0; offset < length; offset += bytes_read)
    {
      chunk = ReadFile(handle:fh, length:length - bytes_read, offset:offset);
      if (isnull(chunk)) break;

      bytes_read += strlen(chunk);
      contents += chunk;
    }
  }
  CloseFile(handle:fh);

  # Parse INI file.
  ini = ini_parse(blob:contents);
  if (!isnull(ini) && ini["Attributes.HttpTunnel"] == "0")
    workaround = TRUE;
}
NetUseDel();

if (workaround) exit(0, "HP LoadRunner 9.52 is installed, but the workaround is in place so the install is not affected.");


# Generate a security report.
if (report_verbosity > 0)
{
  report = '\n  Installed version : ' + major + '.' + minor + '\n';
  if (!file_found)
    report += '\n  ' + full_path + ' not found';
  else if (isnull(ini))
    report += '\n  ' + full_path + ' could not be parsed';
  else if (isnull(ini["Attributes.HttpTunnel"]))
    report += '\n  Could not find variable HttpTunnel in section Attributes';
  else
    report += '\n  HttpTunnel has value ' + ini["Attributes.HttpTunnel"] + ', workaround requires 0';
  report += '\n';

  security_hole(port:port, extra:report);
}
else security_hole(port);
