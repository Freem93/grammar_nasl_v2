#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59035);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/07/12 02:12:33 $");

  script_name(english:"IBM Lotus Symphony Detection");
  script_summary(english:"Detects installs of IBM Lotus Symphony");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains an alternative office suite.");
  script_set_attribute(
    attribute:"description",
    value:
"IBM Lotus Symphony, an office productivity suite, is installed on the
remote Windows host."
  );
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/lotus/symphony/home.nsf/home");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_symphony");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'IBM Lotus Symphony';

# http://www-01.ibm.com/support/docview.wss?uid=swg21369757
ver_ui_map = make_array(
"3.0.1.20121012-2300", "3.0.1 Fix Pack 2",
"3.0.1.20120320-0125", "3.0.1 Fix Pack 1",
"3.0.1.20120110-2000", "3.0.1",
"3.0.0.20110822-1305", "3.0 Fix Pack 3",
"3.0.0.20110707-1500", "3.0 Fix Pack 3",
"3.0.0.20110403-1800", "3.0 Fix Pack 2",
"3.0.0.20101229-1800", "3.0 Fix Pack 1",
"3.0.0.20101015-2340", "3.0",
"3.5.0.20100721-1539", "1.3",
"20090922-1655", "1.3",
"20081124-2154", "1.2",
"20080724-1420", "1.0"
);

login  = kb_smb_login();
port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
pass   = kb_smb_password();
domain = kb_smb_domain();
name   =  kb_smb_name();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Lotus\Symphony\Path";

path = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);

if(isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}

close_registry(close:FALSE);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

item = eregmatch(pattern: "[a-zA-Z]:(.*)", string: path);
if(isnull(item[1]))
{
  NetUseDel();
  exit(1, "Unable to parse path from registry key " + key);
}

dir = item[1] + "framework\shared\eclipse\features\";
fh = FindFirstFile(pattern:dir + "com.ibm.symphony*");

version_list = make_array();

latest_version = NULL;

# iterate through all the packages and find which one has the latest
# version number
while (!isnull(fh))
{
  item = eregmatch(pattern:"[^_]+_([0-9\.-]+)$", string: fh[1]);
  if(isnull(item))
  {
    NetUseDel();
    exit(1, "Unable to extract version information from file name.");
  }

  if(!isnull(latest_version))
  {
    test_ver = item[1];
    # extract build timestamp
    item = eregmatch(pattern:"([0-9]+)-([0-9]+)$", string: test_ver);
    item1 = eregmatch(pattern:"([0-9]+)-([0-9]+)$", string: latest_version);

    if(isnull(item) || isnull(item1))
    {
      NetUseDel();
      exit(1, "Error parsing version strings.");
    }

    # we can't fit the whole timestamp (datet + time) in an int, so we break it
    # apart for comparison
    dt1 = int(item[1]);
    dt2 = int(item1[1]);

    tm1 = int(item[2]);
    tm2 = int(item1[2]);

    # compare build dates first
    if(dt1 > dt2)
      latest_version = test_ver;

    # compare times if dates equal
    if(dt1 == dt2)
    {
      if(tm1 > tm2)
        latest_version = test_ver;
    }
  }
  else latest_version = item[1];

  fh = FindNextFile(handle:fh);  # gets the next file in the directory
}

# cleanup
NetUseDel();

if(isnull(latest_version))
  audit(AUDIT_UNINST, appname);

kb_base = "SMB/Lotus_Symphony/";

set_kb_item(name:kb_base + "Installed", value:TRUE);
set_kb_item(name:kb_base + "Version", value:latest_version);
set_kb_item(name:kb_base + "Path", value:path);

register_install(
  app_name:appname,
  path:path,
  version:latest_version,
  cpe:"cpe:/a:ibm:lotus_symphony");

ver_ui = NULL;
if(isnull(ver_ui_map[latest_version]))
  ver_ui = latest_version;
else
  ver_ui = ver_ui_map[latest_version] + " (" + latest_version + ")";

set_kb_item(name:kb_base + "Version_UI", value:ver_ui);

if (report_verbosity > 0)
{
  report = '\n  Path    : ' + path +
           '\n  Version : ' + ver_ui + '\n';
  security_note(port:port,extra:report);
}
else security_note(port);
