#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24355);
  script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2007-1029");
  script_bugtraq_id(22583);
  script_osvdb_id(33208);

  script_name(english:"EasyMail Objects IMAP4 Component Connect Method Remote Overflow");
  script_summary(english:"Checks version of EasyMail Objects");

 script_set_attribute(attribute:"synopsis", value:
"A COM object on the remote Windows host is affected by a buffer
overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"EasyMail Objects, a set of COM objects for supporting email protocols,
is installed on the remote Windows host.

The IMAP4 component of the version of the DjVu Browser Plug-in
installed on the remote host reportedly is affected by a stack buffer
overflow in the 'Connect' method that can be triggered with a 500+
character hostname. An attacker may be able to leverage this issue to
execute arbitrary code on the remote host subject to the user's
privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cbe0b07");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/460237/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Install the latest version of EasyMail Objects 6.5 or later as that is
rumoured to fix the issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/16");

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


include("smb_func.inc");
include("audit.inc");

# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

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


rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Determine where it's installed.
dll = NULL;
clid = "{703B353E-FA2E-4072-8DDF-F70AAC7E527E}";
key = "SOFTWARE\Classes\CLSID\" + clid +  "\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) dll = value[1];

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);


# If we found the dll...
if (dll)
{
  # Determine its version from the DLL itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:dll);
  dll2 =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:dll);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:dll2,
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

  # There's a problem if the version is < 6.5.0.2
  if (!isnull(ver))
  {
    fix = split("6.5.0.2", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          "Version ", version, " of the EasyMail IMAP4 Object is installed as :\n",
          "\n",
          "  ", dll
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
