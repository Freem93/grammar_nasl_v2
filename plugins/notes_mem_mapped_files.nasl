#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27574);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2007-5544");
  script_bugtraq_id(26146);
  script_osvdb_id(40948);

  script_name(english:"IBM Lotus Notes / Domino Client Memory Mapped Files Privilege Escalation");
  script_summary(english:"Checks version of Lotus Notes and notes.ini settings");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
unauthorized access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Lotus Notes installed on the remote Windows host fails
to adequately protect certain memory mapped files used by the
application for inter-process communications. In a shared user
environment, a local user may be able to leverage this issue to read
from these files, leading to information disclosure, or write to them,
possibly injecting active content such as Lotus Script.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482694/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg21257030");
  script_set_attribute(attribute:"solution", value:
"Upgrade as necessary to Lotus Notes Client version 6.5.6 / 7.0.3 / 8.0
or later and then edit the 'notes.ini' configuration file as described
in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","lotus_notes_installed.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/Lotus_Notes/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

appname = "IBM Lotus Notes";
kb_base = "SMB/Lotus_Notes/";

version = get_kb_item_or_exit(kb_base + 'Version');
ver_ui = get_kb_item_or_exit(kb_base + 'Version_UI');
path = get_kb_item_or_exit(kb_base + 'Path');


# If it's an affected version...
#
# nb: ver[2] is multiplied by 10.
ver = split(version, sep:'.', keep:FALSE);

if (
  (int(ver[0]) == 6 && int(ver[1]) == 5 && int(ver[2]) < 6) ||
  (int(ver[0]) == 7 && int(ver[1]) == 0 && int(ver[2]) < 30)
)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + ver_ui +
      '\n  Fixed version     : 6.5.6 / 7.0.3 / 8.0' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
# Otherwise, make sure the setting is present in notes.ini.
else
{
  # Connect to the appropriate share.
  port    =  kb_smb_transport();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

  path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  ini =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\notes.ini", string:path);
  fh = CreateFile(
    file:ini,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel();
    exit(0);
  }

  # no more than 50k
  data = '';
  chunk = 51200;
  size = GetFileSize(handle:fh);
  if (size > 0)
  {
    if (chunk > size) chunk = size;
    data = ReadFile(handle:fh, length:chunk, offset:0);
  }
  CloseFile(handle:fh);
  NetUseDel();

  if (data)
  {
    # There's a problem if the setting doesn't exist.
    if (!egrep(pattern:"^SharedMemoryAllowOnly=1", string:data))
    {
      security_warning(port);
      exit(0);
    }
  }
}


audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
