#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76166);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_bugtraq_id(68055);
  script_osvdb_id(108102);

  script_name(english:"IDA Kernel Database TIL Section Parsing Unspecified Issue");
  script_summary(english:"Checks for the presence of the mitigating IDA Pro plugin");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an
unspecified flaw.");
  script_set_attribute(attribute:"description", value:
"The version of IDA Pro, an interactive disassembler installed on the
remote host, is 6.0 or newer. It is, therefore, reportedly affected by
an unspecified vulnerability.

This vulnerability is mitigated by an IDA plugin (tilcheck.plw), which
was not detected.

By tricking a user into loading a specially crafted IDB (IDA database)
file into IDA Pro, it may be possible for the attacker to have an
unspecified impact.");
  script_set_attribute(attribute:"see_also", value:"https://www.hex-rays.com/vulnfix.shtml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to 6.5 or 6.6 and download and install the tilcheck plugins
(and any other included files) from the link referenced.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:datarescue:ida_pro");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

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

get_kb_item_or_exit("SMB/Registry/Enumerated");

locations = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/IDA Pro*/InstallLocation");
if (isnull(locations)) audit(AUDIT_NOT_INST, "IDA Pro");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

report = "";
audit_report = "";
vulnerable = FALSE;
not_vuln_versions = make_list();

# Check each installed copy of IDA
foreach key (keys(locations))
{
  path = get_kb_item_or_exit(key);

  version_vulnerable = FALSE;

  # Check the version of the main exe.
  share =  ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =    ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\idaq.exe", string:path);
  plugin = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\plugins\tilcheck.plw", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  # Open the executable
  fh = openfile(file:exe);
  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    continue;
  }

  # Check the executable's version
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  if (isnull(ver))
  {
    NetUseDel(close:FALSE);
    continue;
  }

  # Only want to check up to first two parts of version
  if (max_index(ver) > 2)
  {
    version_cmp = join(make_list(ver[0], ver[1]), sep:'.');
  }
  else
  {
    version_cmp = join(ver, sep:'.');
  }

  version = join(ver, sep:'.');

  if (ver_compare(ver:version_cmp, fix:'6.0', strict:FALSE) == -1 || ver_compare(ver:version_cmp, fix:'6.6', strict:FALSE) == 1)
  {
    not_vuln_versions[max_index(not_vuln_versions)] = version;
  }
  else if (ver_compare(ver:version_cmp, fix:'6.5', strict:FALSE) == 0 || ver_compare(ver:version_cmp, fix:'6.6', strict:FALSE) == 0)
  {
    # Check that the tilcheck.plw plugin exists (it fixes the bug)
    fh = openfile(file:plugin);
    if (!isnull(fh))
    {
      not_vuln_versions[max_index(not_vuln_versions)] = version;
      CloseFile(handle:fh);
    }
    else
    {
      version_vulnerable = TRUE;
    }
  }
  else
  {
    version_vulnerable = TRUE;
  }

  NetUseDel(close:FALSE);

  if (version_vulnerable)
  {
    report +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version + '\n';
    vulnerable = TRUE;
  }
}

NetUseDel();

if (vulnerable)
{
  if (report_verbosity > 0) security_warning(extra:report, port:port);
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, "IDA Pro", not_vuln_versions);
