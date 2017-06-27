#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69316);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/15 16:37:15 $");

  script_cve_id("CVE-2008-3175");
  script_bugtraq_id(30472);
  script_osvdb_id(47545);

  script_name(english:"CA ARCserve Backup for Laptops and Desktops Server, CA Protection Suite, and CA Desktop Management Suite Integer Underflow");
  script_summary(english:"Checks version of rxRPC.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has software installed that is affected by an integer
underflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version of rxRPC.dll installed on the remote host, the
Computer Associates product is affected by an integer underflow
vulnerability that could allow a remote attacker to cause the LGServer
service to crash or execute arbitrary code."
  );
  # https://support.ca.com/irj/portal/anonymous/phpsupcontent?contentID=181721
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f39ff63");
  script_set_attribute(
    attribute:"solution",
    value:"Apply the appropriate patch per the vendor's advisory."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:arcserve_backup_for_laptops_and_desktops");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:brightstor_arcserve_backup_laptops_desktops");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:desktop_management_suite");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ca:protection_suites");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\ComputerAssociates\BrightStor Mobile Backup Server\CurrentVersion\InstallDir";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

check_paths = make_list();

if (!isnull(path) && path != '')
  check_paths = make_list(check_paths, tolower(path));

# Additional hard-coded check paths for CA Protection Suites / CA Desktop Management Suite
check_paths = make_list(
  check_paths,
  tolower("C:\Program Files\CA\BrightStor ARCserve Backup for Laptops & Desktops\server\"),
  tolower("C:\Program Files (x86)\CA\BrightStor ARCserve Backup for Laptops & Desktops\server\"),
  tolower("C:\Program Files\CA\Unicenter DSM\BABLD\Server\"),
  tolower("C:\Program Files (x86)\CA\Unicenter DSM\BABLD\Server\")
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
    fix = '11.1 SP2 (QI85497) with RO00912';
  }
  else if (version =~ "^11\.1\.")
  {
    # fix: RO00912
    # ts: 1213177414
    # Wednesday, June 11, 2008 5:43:34 AM EST
    if (timestamp < 1213177414)
    {
      fix = 'RO00912';
      fix_ts = '1213177414';
    }
  }
  else if (version =~ "^11\.3\.")
  {
    # fix: RO01150
    # ts: 1216636869
    # Monday, July 21, 2008 6:41:09 AM EST
    if (timestamp < 1216636869)
    {
      fix = 'RO01150';
      fix_ts = '1216636869';
    }
  }
  else if (version =~ "^11\.5\.")
  {
    # fix: RO00913
    # ts: 1213177656
    # Wednesday, June 11, 2008 5:47:36 AM EST
    if (timestamp < 1213177656)
    {
      fix = 'RO00913';
      fix_ts = '1213177656';
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
