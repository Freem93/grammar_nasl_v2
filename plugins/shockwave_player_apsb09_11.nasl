#
# (C) Tenable Network Security, Inc.
#


include('compat.inc');


if (description)
{
  script_id(40421);
  script_version('$Revision: 1.15 $');
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id('CVE-2009-0901', 'CVE-2009-2495', 'CVE-2009-2493');
  script_bugtraq_id(35845);
  script_osvdb_id(56696, 56698, 56699);

  script_name(english:'Shockwave Player < 11.5.0.601 Multiple Vulnerabilities (APSB09-11)');
  script_summary(english:'Checks version of Shockwave Player');

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an Internet Explorer plugin which
uses a vulnerable version of the Microsoft Active Template Library
(ATL).");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe's Shockwave Player
that is earlier than 11.5.0.601. Such versions were compiled against a
version of Microsoft's Active Template Library (ATL) that contained a
vulnerability. If an attacker can trick a user of the affected
software into opening such a file, this issue could be leveraged to
execute arbitrary code with the privileges of that user.");
  script_set_attribute(attribute:"see_also", value:"http://blogs.adobe.com/psirt/2009/07/impact_of_microsoft_atl_vulner.html");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb09-11.html");
  script_set_attribute(attribute:"solution", value:
"Uninstall the Internet Explorer version of Shockwave Player version
11.5.0.600 and earlier, restart the system, and then install version
11.5.0.601 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 200, 264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:'Windows');

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies('smb_hotfixes.nasl');
  script_require_keys('SMB/Registry/Enumerated');
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('smb_func.inc');
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item('SMB/Registry/Enumerated')) exit(0, 'SMB/Registry/Enumerated KB item is missing.');
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1, 'Can not connect to IPC$ share.');
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, 'Can not connect to remote registry.');
}

# Check whether it's installed.
variants = make_array();

# - check for the ActiveX control.
clsids = make_list(
  '{4DB2E429-B905-479A-9EFF-F7CBD9FD52DE}',
  '{233C1507-6A77-46A4-9443-F871F945D258}',
  '{166B1BCA-3F9C-11CF-8075-444553540000}'     # used in versions <= 10.x.
);
foreach clsid (clsids)
{
  key = 'SOFTWARE\\Classes\\CLSID\\' + clsid + '\\InprocServer32';
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(item))
    {
      file = item[1];
      variants[file] = 'ActiveX';
    }
    RegCloseKey(handle:key_h);
  }
}

RegCloseKey(handle:hklm);
if (max_index(keys(variants)) == 0)
{
  NetUseDel();
  exit(0, 'Shockwave Player for Internet Explorer is not installed.');
}

# Determine the version of each instance found.
files = make_array();
info = '';

foreach file (keys(variants))
{
  # Don't report again if the name differs only in its case.
  if (files[tolower(file)]++) continue;

  variant = variants[file];

  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:file);
  file2 =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1', string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can not connect to '+share+' share.');
  }

  fh = CreateFile(
    file:file2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);

    if (
      isnull(ver) ||
      (ver[0] == 0 && ver[1] == 0 && ver[2] == 0 && ver[3] == 0)
    )
    {
      NetUseDel();
      exit(1, "Failed to get the file version from '"+file+"'.");
    }

    if (
      ver[0] < 11 ||
      (
        ver[0] == 11 &&
        (
          ver[1] < 5 ||
          (ver[1] == 5 && ver[2] == 0 && ver[3] < 601)
        )
      )
    )
    {
      version = string(ver[0], '.', ver[1], '.', ver[2], '.', ver[3]);

      if (variant == 'ActiveX')
      {
        info += '  - ActiveX control (for Internet Explorer) :\n';
      }

      info += '    ' + file + ', ' + version + '\n';
    }
  }
  NetUseDel(close:FALSE);
}
NetUseDel();


if (!info) exit(0, 'No vulnerable installs of Shockwave Player were found.');

if (report_verbosity > 0)
{
  # nb: each vulnerable instance adds 2 lines to 'info'.
  if (max_index(split(info)) > 2)
    shck = 's';
  else shck = '';

  report = string(
    '\n',
    'Nessus has identified the following vulnerable instance', shck, ' of Shockwave\n',
    'Player for Internet Explorer installed on the remote host :\n',
    '\n',
    info
  );
  security_hole(port:get_kb_item('SMB/transport'), extra:report);
}
else security_hole(get_kb_item('SMB/transport'));
