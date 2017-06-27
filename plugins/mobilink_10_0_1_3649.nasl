#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31719);
  script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2016/05/16 14:12:49 $");

  script_cve_id("CVE-2008-0912");
  script_bugtraq_id(27914);
  script_osvdb_id(42364);
  script_xref(name:"Secunia", value:"29045");

  script_name(english:"MobiLink Server < 10.0.1 build 3649 mlsrv10.exe Multiple Remote Overflows");
  script_summary(english:"Checks version of mlsrv10.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is prone to a buffer
overflow attack.");
 script_set_attribute(attribute:"description", value:
"The version of the SQL Anywhere MobiLink Server installed on the
remote host reportedly is affected by a heap-based buffer overflow
when handling strings such as the username, version, and remote ID
longer than 128 bytes. An unauthenticated attacker may be able to
leverage this issue to execute arbitrary code on the affected system.");
 script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/mobilinkhof-adv.txt");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/488409/100/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/490259/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to SQL Anywhere 10.0.1 build 3649 or later as that reportedly
addresses the issues.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/01");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mobilink_server_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# comment out: do not depend on remote check, which would fail in agent mode

# Unless we're paranoid, make sure the service is running.
#if (report_paranoia < 2)
#{
#  mobilink_port = get_kb_item("Services/mobilink");
#  if (!mobilink_port) mobilink_port = 2439;
#  if (!get_port_state(mobilink_port)) exit(0);
#}
#else mobilink_port = kb_smb_transport();


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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


# Determine where it's installed.
path = NULL;

key = "SOFTWARE\Sybase\SQL Anywhere";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"Location");
        if (!isnull(value)) path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:value[1]);
        RegCloseKey(handle:key2_h);
      }
    }
    if (!isnull(path)) break;
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Check the version of the exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\win32\mlsrv10.exe", string:path);
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
  fix = split("10.0.1.3649", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        version = string(ver[0], ".", ver[1]);
        report = string(
          "\n",
          "Version ", version, " of the MobiLink Server is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
