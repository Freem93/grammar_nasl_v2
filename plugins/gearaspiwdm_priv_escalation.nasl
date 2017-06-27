#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34488);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_bugtraq_id(31089);
  script_xref(name:"CERT", value:"146896");

  script_name(english:"GEAR Software CD DVD Filter Driver Insecure Method Local Privilege Escalation");
  script_summary(english:"Checks version of GEARAspiWDM.sys");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a kernel driver with an insecure method.");
  script_set_attribute(attribute:"description", value:
"The version of GEAR Software's CD DVD Filter kernel driver
(GEARAspiWDM.sys) on the remote host contains an insecure method that
allows a local user to make an unlimited number of calls to
'IoAttachDevice' from user-land, thereby enabling him to exploit a
local privilege escalation flaw in the Microsoft Windows kernel in the
'IopfCompleteRequest' function.

Note that this driver may have been installed as part of a third-party
application such as Apple iTunes, Norton 360, Norton Ghost, Norton
Save and Restore, Backup Exec System Recovery, or Symantec LiveState
Recovery.");
  script_set_attribute(attribute:"see_also", value:"http://www.wintercore.com/advisories/advisory_W021008.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/497131/30/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb341a9b" );
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.10.07a.html" );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3025" );
  script_set_attribute(attribute:"solution", value:
"Contact the appropriate vendor for an upgrade and verify that the
version of the kernel driver is 2.0.7.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

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

# Grab the file version of the affected file.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\drivers\GEARAspiWDM.sys", string:winroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:sys,
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
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  fix = split("2.0.7.5", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Path    : ", winroot, "\\system32\\drivers\n",
          "Version : ", ver[0], ".", ver[1], ".", ver[2], ".", ver[3], "\n"
        );
        security_hole(port:get_kb_item("SMB/transport"), extra:report);
      }
      else security_hole(get_kb_item("SMB/transport"));
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
