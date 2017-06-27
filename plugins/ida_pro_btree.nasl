#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69180);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/07/14 18:12:04 $");

  script_bugtraq_id(60116);
  script_osvdb_id(93561);

  script_name(english:"IDA Pro IDB Loader Code Execution");
  script_summary(english:"Checks for the presence of the mitigating IDA Pro plugin.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IDA Pro, an interactive disassembler installed on the
remote host, is between versions 6.1 and 6.7. It is, therefore,
affected by a code execution vulnerability. A remote attacker can
exploit this, by convincing a user into loading a specially crafted
IDB (IDA database) file into IDA Pro, to execute arbitrary code.

The vulnerability is mitigated by an IDA plugin (btval.plw), which
was not detected.");
  script_set_attribute(attribute:"see_also", value:"https://www.hex-rays.com/vulnfix.shtml");
  script_set_attribute(attribute:"solution", value:
"Download and install the btval plugins (and any other included files)
from the referenced vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

locations = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/IDA Pro*/InstallLocation");
if (isnull(locations)) audit(AUDIT_NOT_INST, "IDA Pro");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

function cleanup()
{
  NetUseDel();
  audit(_FCT_ANON_ARGS[0], _FCT_ANON_ARGS[1]);
}

function openfile(file)
{
  return CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
}

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

report = "";
audit_report = "";
vulnerable = FALSE;

# Check each installed copy of IDA
foreach key (keys(locations))
{
  # This will fork
  path = get_kb_item_or_exit(key);

  # Check the version of the main exe.
  share =  ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =    ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\idaq.exe", string:path);
  plugin = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\plugins\btval.plw", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    cleanup(AUDIT_SHARE_FAIL, share);
  }

  # Open the executable
  fh = openfile(file:exe);
  if (isnull(fh))
  {
    audit_report += 'No idaq.exe found at ' + path + '.\n';
    NetUseDel(close:FALSE);
    continue;
  }

  # Check the executable's version
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  if (isnull(ver))
  {
    audit_report += 'Error getting the version from idaq.exe at ' + path + '.\n';
    NetUseDel(close:FALSE);
    continue;
  }

  # Check that the installed version is >= 6.1 and < 6.7.
  # Reportedly, the fix was integrated into 6.7 and so the plugin is not required.
  version = join(ver, sep:'.');
  if (ver_compare(ver:version, fix:'6.1', strict:FALSE) == -1 ||
      ver_compare(ver:version, fix:'6.7', strict:FALSE) >= 0)
  {
    audit_report += 'IDA version ' + version + ' at ' + path + ' is not vulnerable.\n';
  }
  else
  {
    # Check that the btval.plw plugin exists (it fixes the bug)
    fh = openfile(file:plugin);
    if (!isnull(fh))
    {
      audit_report += 'IDA version ' + version + ' at ' + path + ' is patched.\n';
      CloseFile(handle:fh);
    }
    else
    {
      report +=
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version + ' (unpatched)\n';
      vulnerable = TRUE;
    }
  }

  NetUseDel(close:FALSE);
}

NetUseDel();

if (vulnerable)
{
  if (report_verbosity > 0) security_hole(extra:report, port:port);
  else security_hole(port);
}
else exit(0, audit_report);
