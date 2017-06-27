#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69317);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id(
    "CVE-2007-3216",
    "CVE-2007-5003",
    "CVE-2007-5004",
    "CVE-2007-5005",
    "CVE-2007-5006",
    "CVE-2008-1328",
    "CVE-2008-1329"
  );
  script_bugtraq_id(
    24348,
    28616
  );
  script_osvdb_id(
    35329,
    41350,
    41351,
    41352,
    41353,
    44320,
    44328
  );

  script_name(english:"CA ARCserve Backup for Laptops and Desktops Server and CA Desktop Management Suite Multiple Remote Vulnerabilities");
  script_summary(english:"Checks version of rxRPC.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by multiple
remote vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version of rxRPC.dll installed on the remote host, the
Computer Associates product is affected by multiple vulnerabilities that
could allow a remote attacker to execute arbitrary code on the host."
  );
  # https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=173105
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c393da3");
  script_set_attribute(
    attribute:"solution",
    value:"Apply the appropriate patch per the vendor's advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor ARCserve for Laptops and Desktops LGServer Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(22, 119, 189, 287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup_for_laptops_and_desktops");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:brightstor_arcserve_backup_laptops_desktops");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:desktop_management_suite");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

registry_init();
port = kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

key_list = make_list(
  # BABLD (Server) 11.5 / 11.1
  "SOFTWARE\ComputerAssociates\BrightStor Mobile Backup Server\CurrentVersion\InstallDir",
  # BABLD (Explorer) 11.5
  "SOFTWARE\ComputerAssociates\BrightStor Mobile Backup Manager GUI\CurrentVersion\InstallDir",
  # BABLD (Explorer) 11.1
  "SOFTWARE\ComputerAssociates\BrightStor Mobile Backup Admin Gui\CurrentVersion\InstallDir"
);

check_paths = make_list();

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
foreach key (key_list)
{
  path = get_registry_value(handle:hklm, item:key);
  if (!isnull(path) && path != '')
    check_paths = make_list(check_paths, tolower(path));
}

RegCloseKey(handle:hklm);

# Additional hard-coded check paths for CA Desktop Management Suite
check_paths = make_list(
  check_paths,
  tolower("C:\Program Files (x86)\CA\DSM\BABLD\MGUI\"),
  tolower("C:\Program Files\CA\DSM\BABLD\MGUI\")
);

check_paths = list_uniq(check_paths);

info = '';

foreach path (check_paths)
{
  file = path + 'rxRPC.dll';

  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:file);
  dll =  ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1', string:file);

  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
    continue;

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh)) continue;

  ver = GetFileVersion(handle:fh);
  if (!isnull(ver))
    version = join(ver, sep:'.');
  else
    continue;

  ret = GetFileVersionEx(handle:fh);
  CloseFile(handle:fh);

  if (!isnull(ret))
    timestamp = int(ret['dwTimeDateStamp']);
  else
    continue;

  fix = '';
  fix_ts = '';

  if (version =~ "^11\.0\.")
  {
    fix = '11.1 SP2 (QI85497) with QO95512';
  }
  else if (version =~ "^11\.1\.")
  {
    # fix: QO95512
    # ts: 1203315832
    # Monday, February 18, 2008 1:23:52 AM EST
    if (timestamp < 1203315832)
    {
      fix = 'QO95512';
      fix_ts = '1203315832';
    }
  }
  else if (version =~ "^11\.5\.")
  {
    # fix: QO95513
    # ts: 1203318093
    # Monday, February 18, 2008 2:01:33 AM EST
    if (timestamp < 1203318093)
    {
      fix = 'QO95513';
      fix_ts = '1203318093';
    }
  }

  if (fix != '')
  {
    info +=  '\n  Path            : ' + file +
             '\n  Version         : ' + version +
             '\n  Timestamp       : ' + timestamp;
    if (fix_ts != '')
      info += '\n  Fixed Timestamp : ' + fix_ts;
    info += '\n  Required Patch  : ' + fix + '\n';
  }
}

NetUseDel();

if (info != '')
{
  if (report_verbosity > 0)
  {
    report = '\nNessus found the following unpatched rxRPC.dll files :\n' + info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}

exit(0, 'No vulnerable CA products found.');
