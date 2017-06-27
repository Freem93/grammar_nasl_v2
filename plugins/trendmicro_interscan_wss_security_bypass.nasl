#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35648);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_cve_id("CVE-2009-0613");
  script_bugtraq_id(33679);
  script_osvdb_id(51881);
  script_xref(name:"Secunia", value:"33867");

  script_name(english:"Trend Micro InterScan Web Security Suite < 3.1 Build 1237 Multiple Flaws");
  script_summary(english:"Checks about.exe version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
security bypass vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Trend Micro InterScan Web Security Suite is installed on the remote
host. The installed version fails to restrict non-admin accounts
'Auditor' and 'Report Only' from modifying system configurations even
though these accounts do not have sufficient permissions.");
   # http://www.trendmicro.com/ftp/documentation/readme/iwss_31_win_en_readme_CP_1237_EN.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?691e227e");
  script_set_attribute(attribute:"solution", value:"Upgrade to Trend Micro InterScan Web Security Suite 3.1 Build 1237.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:interscan_web_security_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","http_version.nasl","iwss_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports("Services/www", 1812, 139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");
include("misc_func.inc");

if (report_paranoia < 2)
{
  # Check if we can find an instance of Trend Micro InterScan Web Security Suite
  found = 0;
  ports = add_port_in_list(list:get_kb_list("Services/www"), port:1812);

  foreach port (ports)
  {
    if (get_kb_item(string("Services/www/",port,"/iwss")))
    {
      found++;
      break;
    }
  }
  if (!found) exit(0);
}

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

# Connect to the appropriate share.

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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

# Figure out where it is installed.
path = NULL;

key = "SOFTWARE\TrendMicro\InterScan Web Security Suite";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Program Directory");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of about.exe
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\about.exe", string:path);

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
  fix = split("3.1.0.1237", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "InterScan Web Security Suite version ", ver[0], ".", ver[1], "\n",
          "build ",ver[3], "is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
