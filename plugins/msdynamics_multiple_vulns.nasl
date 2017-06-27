#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(33395);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id("CVE-2006-5265", "CVE-2006-5266");
  script_bugtraq_id(29991);
  script_osvdb_id(48819, 48820, 48821);

  script_name(english:"Microsoft Dynamics GP < 10.0 Multiple Vulnerabilities");
  script_summary(english:"Checks for vulnerable version of Microsoft Dynamics GP");

 script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"Microsoft Dynamics GP (formerly known as Great Plains), is installed
on remote host. The installed version of Microsoft Dynamics GP is
affected by multiple vulnerabilities.

  - By sending a specially crafted DPS message with a very
    long IP address or a string, to Distributed Process
    Server (DPS) or Distributed Process Manager (DPM), it
    may be possible to overflow a buffer or execute
    arbitrary code on the remote system.

  - By sending a specially crafted DPS message, containing
    an invalid magic number, it may be possible to cause a
    denial of service condition and crash the remote system.

  - By sending a specially crafted DPM message, it may be
    possible to execute arbitrary code on the remote system.

It should be noted that code execution will generally result in a
complete compromise of the affected system.");
 script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/25840");
 script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/25841" );
 script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/25842" );
 script_set_attribute(attribute:"see_also", value:"http://xforce.iss.net/xforce/xfdb/25844" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Microsoft Dynamics GP 10.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/03");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");

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

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

path = NULL;
disp_version = NULL;

key = "SOFTWARE\Microsoft\Business Solutions\Great Plains";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
   # Try to be locale independent.
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey + "\DEFAULT\SETUP";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"AppPath");
        if (!isnull(value)) path = value[1];

        value = RegQueryValue(handle:key2_h, item:"Version");
        if (!isnull(value)) disp_version = value[1];

        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (!path)
{
 NetUseDel();
 exit(0);
}
NetUseDel(close:FALSE);


share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Dps.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(file:exe,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

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
  # nb :
  # Current version is 10.0.193.0, but report
  # only if version is less than 10.0.

  fix = split("10.0", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0 && disp_version)
      {
        report = string(
          "\n",
          "Version ", disp_version, " of Microsoft Dynamics GP is installed under :\n",
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
