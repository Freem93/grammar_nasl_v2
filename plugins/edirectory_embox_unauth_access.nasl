#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31850);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2008-0926");
  script_bugtraq_id(28441);
  script_osvdb_id(43690);
  script_xref(name:"Secunia", value:"29527");

  script_name(english:"Novell eDirectory eMBox Utility Unauthorized Access");
  script_summary(english:"Checks version of eDirectory service embox.nlm");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that may allow
unauthorized access to the system.");
  script_set_attribute(attribute:"description", value:
"The remote host is running eDirectory, a popular directory service
software from Novell.

A vulnerability in the eMBox utility included with the software, may
allow an unauthenticated attacker to access local files or cause a
denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/May/54");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.novell.com/support/viewContent.do?externalId=3477912"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to eDirectory 8.8.2 or rename 'embox.nlm'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_cwe_id(287);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:edirectory");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

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

# Connect to HKLM
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

# Check if NDS is installed
key = NULL;
edir_name = NULL;
edir_path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NDSonNT";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If eDirectory is installed...
  item = RegQueryValue(handle:key_h, item:"DisplayName");
  if (!isnull(item))
  {
    edir_name = item[1];
  }
  RegCloseKey(handle:key_h);
}

# Get the share where edir is installed.

key = "SYSTEM\CurrentControlSet\Services\NDS Server0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"ImagePath");
  if (!isnull(item))
  {
    edir_path = item[1];
    edir_path = str_replace(string:edir_path,find:'"',replace: "");
  }
  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);

# Exit if eDirectory is not installed.

if ("Novell eDirectory" >!< edir_name || isnull(edir_name) || isnull(edir_path))
{
  NetUseDel();
  exit(0);
}

share  = ereg_replace(pattern:"^([A-Za-z]):.*$", replace:"\1$", string:edir_path);
share2 = ereg_replace(pattern:"\$", replace:":", string:share);
nlm =   "\\novell\\NDS\\embox.dlm";

NetUseDel(close:FALSE);

# Connect to the appropriate share
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:nlm,
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
  # Version of eMBox service for eDirectory 8.8 SP2
  fix = split("202.14.4.0", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
	version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          "\n",
          "Version ", version, " of eMBox.nlm is installed under :\n",
          "\n",
          "  ", share2, "\\novell\\NDS\\embox.dlm\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
