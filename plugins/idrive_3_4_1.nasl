#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55549);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/19 01:42:50 $");

  script_bugtraq_id(48582);

  script_name(english:"IDrive Online Backup ActiveX Control < 3.4.1 Arbitrary File Overwrite");
  script_summary(english:"Checks for control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows overwriting
arbitrary files.");
  script_set_attribute(attribute:"description", value:
"The version of IDrive installed on the remote Windows host is earlier
than 3.4.1 and includes a third-party ActiveX control named
UniBasicPack.UniTextBox from CyberActiveX with an insecure method.
Specifically, the 'SaveToFile()' method can be abused to overwrite
arbitrary files.

Note that this control implements IObjectSafety, which reports that it
is safe for both initialization and scripting, even though it is not
marked as such in the registry itself.");
  # http://www.htbridge.ch/advisory/idrive_online_backup_activex_control_insecure_method.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcb69223");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2011/Jul/51"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to IDrive 3.4.1 or later, which does not include the control.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
include("smb_activex_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");


# Check first for the ActiveX control.
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");

clsid = '{979AE8AA-C206-40EC-ACA7-EC6B6BD7BE5E}';
info = "";

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "The control is not installed as the class id '"+clsid+"' is not defined.");
}

version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  exit(1, "Failed to get file version of '"+file+"'.");
}

if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info = '\n  Class Identifier          : ' + clsid +
         '\n  Filename                  : ' + file +
         '\n  Installed ActiveX version : ' + version;
}
activex_end();

if (!info) exit(0, "Version "+version+" of the control is installed as "+file+", but its kill bit is set.");


# Make sure we're looking at IDrive.
#
# nb: we don't have any info about whether other installs of the
#     control are affected so we're only flagging those from IDrive.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+$', replace:"\1", string:file);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\IDriveEClsClient.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Version "+version+" of the control is installed as "+file+", but it does not appear to have been installed with IDrive.");
}

fsize = GetFileSize(handle:fh);
ofs = 0;
chunk = 16384;

magic = "Version No: ";
version = NULL;
version_pat = magic + "([0-9.]+)";

while (fsize > 0 && ofs <= fsize && !version)
{
  data = ReadFile(handle:fh, length:chunk, offset:ofs);
  if (strlen(data) == 0) break;
  data = str_replace(find:raw_string(0), replace:"", string:data);

  if (magic >< data)
  {
    match = eregmatch(pattern:version_pat, string:data);
    if (match)
    {
      version = match[1];
      break;
    }
  }

  # nb: re-read a little bit to make sure we didn't start reading
  #     in the middle of the line.
  ofs += chunk - 512;
}
CloseFile(handle:fh);
NetUseDel();

if (isnull(version)) exit(1, "Couldn't extract the file version from '"+(share-'$')+":"+exe+"'.");


# Make sure we don't flag later versions of IDrive, in case
# those later include the control again.
if (ver_compare(ver:version, fix:"3.4.1.0", strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = info + '\n  Installed IDrive version  : ' + version + '\n';
    if (report_paranoia > 1)
    {
      report +=
        '\n' +
        'Note, though, that Nessus did not check whether the kill bit was\n' +
        'set for the control\'s CLSID because of the Report Paranoia setting\n' +
        'in effect when this scan was run.\n';
    }
    else
    {
      report +=
        '\n' +
        'Moreover, its kill bit is not set so it is accessible via Internet\n' +
        'Explorer.\n';
    }

    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, "IDrive version "+version+" is installed and thus not affected.");
