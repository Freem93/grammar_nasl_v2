#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53332);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2011-1560");
  script_bugtraq_id(47137);
  script_osvdb_id(71494);
  script_xref(name:"TRA", value:"TRA-2011-02");
  script_xref(name:'Secunia', value:'44030');

  script_name(english:"IBM solidDB Password Hash Length Authentication Bypass");
  script_summary(english:"Checks build date of solid.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an authentication bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its build date, the version of IBM solidDB installed on
the remote host is affected by an authentication bypass vulnerability
because the application allows a remote attacker to specify the length
of a password hash. A remote attacker, exploiting this flaw, could
bypass authentication to the database.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2011-02");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-115/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/24");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21474552");
  script_set_attribute(attribute:"solution", value:"Apply the fix specified in the vendor's advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:soliddb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","soliddb_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

if (report_paranoia < 2) get_kb_item_or_exit('Services/soliddb');

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Get the install path
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
if (rc != 1)
{
  NetUseDel();
  exit(1,'Can\'t connect to IPC$ share.');
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1,'Can\'t connect to the remote registry.');
}

# First check the app paths registry for solidDB
paths = make_list();

key = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\solid.exe';
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If SolidDB is installed...
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
    paths = make_list(paths, item[1]);

  RegCloseKey(handle:key_h);
}

# We can have multiple installs, so check the Uninstall hive to be sure

list = get_kb_list('SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
if (isnull(list)) exit(1, 'Could not get Uninstall KB.');

item = NULL;
installstrings = make_list();
foreach name (keys(list))
{
  prod = list[name];
  if (prod && "solidDB " >< prod)
  {
    item = ereg_replace(pattern:'^SMB\\/Registry\\/HKLM\\/(SOFTWARE\\/Microsoft\\/Windows\\/CurrentVersion\\/Uninstall\\/.+)\\/DisplayName$', replace:'\\1', string:name);
    installstrings = make_list(installstrings, str_replace(find:'/', replace:'\\', string:item));
  }
}

# Build an array of installs
if(max_index(installstrings) > 0)
{
  for (i=0; i<max_index(installstrings); i++)
  {
    key_h = RegOpenKey(handle:hklm, key:installstrings[i], mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      # If SolidDB is installed...
      item = RegQueryValue(handle:key_h, item:'InstallLocation');
      if (!isnull(item))
        paths = make_list(paths, item[1] + '\\bin');

      RegCloseKey(handle:key_h);
    }
  }
}
RegCloseKey(handle:hklm);

if(max_index(paths) == 0)
{
  NetUseDel();
  exit(0, 'IBM solidDB does not appear to be installed on the remote host.');
}

# Loop through and check each install
paths = list_uniq(paths);
vuln = 0;
report = NULL;
foreach path (paths)
{
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  exe =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\solid.exe', string:path);

  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can\'t connect to '+ share + ' share.');
  }

  fh = CreateFile(
    file:exe,
  	desired_access:GENERIC_READ,
  	file_attributes:FILE_ATTRIBUTE_NORMAL,
  	share_mode:FILE_SHARE_READ,
	  create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    NetUseDel(close:FALSE);
    debug_print('Can\'t open the file '+path+'\\solid.exe.');
    continue;
  }

  ver = GetFileVersion(handle:fh);
  if (isnull(ver))
  {
    CloseFile(handle:fh);
    NetUseDel();
    debug_print('Couldn\'t get the version of '+path+'\\solid.exe.');
    continue;
  }
  info = GetFileVersionEx(handle:fh);
  CloseFile(handle:fh);

  if (isnull(info) || isnull(info['dwTimeDateStamp']))
  {
    debug_print('Couldn\'t parse the timestamp from '+path+'\\solid.exe.');
    CloseFile(handle:fh);
    continue;
  };
  epochtime = NULL;
  if (ver[0] == 4 && ver[1] == 5)  epochtime = '1291105462';
  else if (ver[0] == 6 && ver[1] == 0) epochtime = '1286785965';
  else if (ver[0] == 6 && ver[1] == 30) epochtime = '1282632983';
  else if (ver[0] == 6 && ver[1] == 5) epochtime = '1286199318'; # 64-bit build date. 32-bit build date is 1291238617
  if (epochtime && info['dwTimeDateStamp'] < epochtime)
  {
    vuln++;
    report +=
      '\n  Path            : ' + path +
      '\n  Version         : ' + join(ver, sep:'.') +
      '\n  Timestamp       : ' + info['dwTimeDateStamp'] +
      '\n  Fixed Timestamp : ' + epochtime + '\n';
  }
}

# Clean up
NetUseDel();

if (report)
{
  if (report_verbosity > 0)
  {
    if (vuln > 1) s = 's of solidDB were found ';
    else s = ' of solidDB was found ';
    report =
      '\n  The following vulnerable install' + s + 'on the' +
      '\n  remote host :' +
      '\n' +
      report;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
exit(0, 'No vulnerable solidDB installs were detected on the remote host.');
