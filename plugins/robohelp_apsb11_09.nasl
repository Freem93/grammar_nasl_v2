#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54602);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/13 21:07:13 $");

  script_cve_id("CVE-2011-0613");
  script_bugtraq_id(47839);
  script_osvdb_id(72317);
  script_xref(name:"Secunia", value:"44480");

  script_name(english:"Adobe RoboHelp FlashHelp Unspecified XSS (APSB11-09) (credentialed check)");
  script_summary(english:"Checks for patched files");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of RoboHelp on the remote host contains a cross-site
scripting vulnerability in its FlashHelp and FlashHelp Pro output. An
attacker may be able to leverage this issue to execute arbitrary
script code in the browser of an authenticated user in the context of
the affected site and to steal cookie-based authentication
credentials.

Note that this plugin checks for a version of RoboHelp that would
generate FlashHelp and FlashHelp Pro projects with a cross-site
scripting vulnerability rather than published projects with the
vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb11-09.html");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory above. Once the
patch is applied, all FlashHelp and FlashHelp Pro files need to be
regenerated.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:robohelp");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

# Connect to IPC share.
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

# Get the installation path from the registry.
base = NULL;
key1 = "SOFTWARE\Adobe\RoboHTML";
key1_h = RegOpenKey(handle:hklm, key:key1, mode:MAXIMUM_ALLOWED);
if (!isnull(key1_h))
{
  # Information is stored in a sub-key named w/ version number.
  info = RegQueryInfoKey(handle:key1_h);
  for (i = 0; i < info[1]; i++)
  {
    # Ignore subkeys that don't look like version numbers.
    version = RegEnumKey(handle:key1_h, index:i);
    if (!strlen(version) || version !~ "^[78]+\.") continue;

    # Open up key for RoboHTML's installed version.
    key2 = key1 + "\" + version;
    key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key2_h))
    {
      item = RegQueryValue(handle:key2_h, item:"InstallFolder");
      if (!isnull(item))
        base = ereg_replace(string:item[1], pattern:"^(.+)\\$", replace:"\1");
      RegCloseKey(handle:key2_h);
    }

    if (!isnull(base)) break;
  }
  RegCloseKey(handle:key1_h);
}

# Clean up.
RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Check if RoboHelp is installed.
if (isnull(base))
{
  NetUseDel();
  exit(0, "RoboHelp 7 or 8 does not appear to be installed.");
}

# Split the software's location into components.
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
path = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
dir = "\RoboHTML\WildFireExt\template_stock";
path_status = dir + "\wf_status.htm";

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

# Try and read one of the affected files.
blob = NULL;
fh = CreateFile(
  file:path + path_status,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  len = GetFileSize(handle:fh);
  if (len)
    blob = ReadFile(handle:fh, length:len, offset:0);
  CloseFile(handle:fh);
}

# Clean up.
NetUseDel();

# Ensure that the HTML file actually existed.
if (isnull(blob))
  exit(1, "RoboHelp " + version + " does not appear to be fully installed.");

# Ensure that the HTML file has a couple things in it that are likely to be
# unique to the vulnerable file we're looking for.
if ('sHtml += "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";' >!< blob)
  exit(0, "RoboHelp " + version + " on the remote host does not appear to be affected.");
if ('strObject += "<PARAM NAME=\'movie\' VALUE=\'"+status_swf+"\'>";' >!< blob)
  exit(0, "RoboHelp " + version + " on the remote host has been fixed and is not affected.");

# Report our findings.
set_kb_item(name:"www/0/XSS", value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + base +
    '\n  Installed version : ' + version +
    '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
