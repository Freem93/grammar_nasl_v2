#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25710);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/11 13:32:18 $");

  script_cve_id("CVE-2007-3906");
  script_bugtraq_id(24932);
  script_osvdb_id(36127);

  script_name(english:"Kaspersky Anti-Virus for Check Point FireWall-1 Unspecified DoS");
  script_summary(english:"Checks product version");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is prone to a
denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The version of Kaspersky Anti-Virus for Check Point FireWall-1
installed on the remote host suffers from an as-yet unspecified issue
in which the antivirus kernel may freeze.");
  script_set_attribute(attribute:"see_also", value:"http://support.kaspersky.com/checkpoint?qid=208279464");
  script_set_attribute(attribute:"solution", value:
"Apply Critical Fix 1 for Kaspersky Anti-Virus 5.5 for Check Point
FireWall-1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kaspersky_lab:kaspersky_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_activex_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Find installation path using one of the app's ActiveX controls.
if (activex_init() != ACX_OK) exit(0);

path = NULL;
clsids = make_list(
  "{0516825F-D051-4E11-BC1D-A6240791074A}",
  "{0C7833BF-CC58-4E22-8A3E-8C60983690D4}"
);
foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (file)
  {
    path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:file);
    break;
  }
}
activex_end();
if (isnull(path)) exit(0);


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of the affected file.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Kav4cpf1.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  fix = split("5.5.161.0", sep:'.', keep:FALSE);
  for (i=0; i<4; i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
      report = string(
        "\n",
        "Version ", version, " of Kaspersky Anti-Virus for Check Point FireWall-1 is\n",
        "installed under :\n",
        "\n",
        "  ", path
      );
      security_warning(port:port, extra:report);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
