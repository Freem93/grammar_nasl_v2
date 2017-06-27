#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58989);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/02/03 20:48:28 $");

  script_cve_id("CVE-2012-0270");
  script_bugtraq_id(52144);
  script_osvdb_id(79491, 79492);
  script_xref(name:"EDB-ID", value:"18710");

  script_name(english:"Csound getnum() getnum Function Multiple Buffer Overflows");
  script_summary(english:"Checks version of Csound install");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an application installed that is affected by
multiple buffer overflow vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Csound installed on the remote Windows host is less
than 5.16.6.  As such, it is reportedly affected by multiple stack-
based buffer overflows present in the getnum() function located in
util/heti_main.c and util/pv_import.c

By tricking a user into opening a specially crafted file, an attacker
may be able to execute arbitrary code subject to the user's
privileges."
  );
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2012-3/");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b3b83d2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Csound version 5.16.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Csound hetro File Handling Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:csounds:csound");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0); 
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");

appname = 'Csound';
port = get_kb_item("SMB/transport");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Classes\CsoundFile\DefaultIcon";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (isnull(key_h))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

res = RegQueryValue(handle:key_h);
RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);

if (isnull(res))
{
  close_registry();
  exit(1, "Unable to get read the registry key 'HKLM\" + key + "'."); 
}

item = eregmatch(pattern: "(.+)bin\\[^\\]+\.exe,0", string: res[1]);
if (isnull(item))
{
  close_registry();
  exit(1, "Failed to get the path from the registry key 'HKLM\" + key + "'.");
}
close_registry(close:FALSE);

path = item[1];

version_file = ereg_replace(pattern:"^[A-Za-z]:(.*)\\?", 
                            replace:"\1\include\version.h", string:path);
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);

if (isnull(rc))
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:version_file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Evidence of a previous Csound installation exists in the Windows Registry (HKLM\" + key + "), but it does not currently appear to be installed."); 
}

content = "";
  
length = GetFileSize(handle:fh);
content = ReadFile(handle:fh, offset:0, length:length);
CloseFile(handle:fh);

NetUseDel();

if (content == "")
  exit(1, "Failed to read '" + path + "include\version.h'.");

#define CS_VERSION          (5)
#define CS_SUBVER           (16)
#define CS_PATCHLEVEL       (2)
#define CS_APIVERSION       2   /* should be increased anytime a new version
#define CS_APISUBVER        6   /* for minor changes that will still allow

major_ver = NULL;
sub_ver = NULL;
patchlevel = NULL;

item = eregmatch(pattern: "CS_VERSION[ \t]+\(([0-9]+)\)", string: content);
if (!isnull(item[1]))  major_ver = item[1];
item = eregmatch(pattern: "CS_SUBVER[ \t]+\(([0-9]+)\)", string: content);
if (!isnull(item[1])) sub_ver = item[1];
item = eregmatch(pattern: "CS_PATCHLEVEL[ \t]+\(([0-9]+)\)", string: content);
if (!isnull(item[1])) patchlevel = item[1];

version = NULL;
if (!isnull(major_ver) && !isnull(sub_ver) && !isnull(patchlevel))
  version = major_ver + '.' + sub_ver + '.' + patchlevel;

if (isnull(version))
  exit(1, "Unable to extract version information from '" + path + "include\version.h'.");

set_kb_item(name:"SMB/Csound/Installed", value:TRUE);
set_kb_item(name:"SMB/Csound/Version", value:version); 
set_kb_item(name:"SMB/Csound/Path", value:path); 

api_major = NULL;
api_subver = NULL;

item = eregmatch(pattern: "CS_APIVERSION[ \t]+([0-9]+)[^0-9]", string: content);
if (!isnull(item[1])) api_major = item[1];

item = eregmatch(pattern: "CS_APISUBVER[ \t]+([0-9]+)[^0-9]", string: content);
if (!isnull(item[1])) api_subver = item[1];

if (!isnull(api_major) && !isnull(api_subver))
{
  api_version = api_major + '.' + api_subver;
  set_kb_item(name:"SMB/Csound/APIVersion", value:api_version);
}

if (ver_compare(ver:version, fix:'5.16.6', strict:FALSE) == -1)
{
  if (report_verbosity > 0) 
  {
    report = '\n  Path              : ' + path +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 5.16.6\n';
    security_hole(port:port,extra:report);
  }
  else security_hole(port);
  exit(0);
} 
else audit(AUDIT_INST_VER_NOT_VULN, appname, version);
