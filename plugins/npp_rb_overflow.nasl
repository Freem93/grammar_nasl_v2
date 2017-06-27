#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25294);
  script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2007-2666");
  script_bugtraq_id(23961);
  script_osvdb_id(36007);

  script_name(english:"Notepad++ Ruby Source File Handling Overflow");
  script_summary(english:"Checks version of Notepad++");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is subject to a buffer
overflow attack.");
 script_set_attribute(attribute:"description", value:
"Notepad++, a free source code editor and Notepad replacement, is
installed on the remote Windows host.

The version of Notepad++ installed on the remote host reportedly
contains a buffer overflow involving how it processes Ruby source code
files. If an attacker can trick a user on the affected host into
opening a specially crafted file of this type using Notepad++, he can
leverage this issue to execute arbitrary code on the host subject to
the user's privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/468529/100/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3924c238" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Notepad++ version 4.1.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/24");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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


# Get some info about the install.
path = NULL;

key = "SOFTWARE\Notepad++";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (path)
{
  # Make sure the executable exists.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\notepad++.exe", string:path);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL,share);
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

  # There's a problem if the version is < 4.1.2.0.
  if (!isnull(ver))
  {
    fix = split("4.1.2.0", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        # nb: only the first 3 parts seem to be reported to end-users.
        version = string(ver[0], ".", ver[1], ".", ver[2]);

        report = string(
          "Notepad++ version ", version, " is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);

        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}


# Clean up.
NetUseDel();
