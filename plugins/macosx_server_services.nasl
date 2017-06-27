#TRUSTED 2ac2ffb5f3d5e3508687b1fffec467d457e8e817a595a4ef72deb71a04f29ee82ed4e23871ceb632be61f2a873b01b0302c926b75c9088d2edbe0f7b37a6e2414862e75a18b6e9883c3d26ccebf392cbeac3a4635b46fb25f2a365fa7b54dc12998a4f0fcc8ec3b0d33aa50e7c4fa9a14ceeb17b9763280b0b14342d8620b01fd256619720e2468784e9d755b71412cdd09b2307f3f888f6b6ad58eba539472d3c438db94d3daf22cd24d48637404b701d6e5041a31ac4d1bbb3bceb1cc2c6b749b0c4264e5f5722706d338132ac18ad820217fc29388160c22ab3d11c99d059576a11196241a4dc541bd628f7232cd4c4b1fc87a53b9ac190a9a721b433bee98d9edcd3455f17c6c6727048775239fb905d22ba4eb12c23e9c1e3803983f5c1ae288c79e7fbe35a009af83dff0ecd7863712bfcebe770f3d2fcbb2d7334abe285fcede81b49d727856473466d08afa24f3a9f1d5231e48ec92a01007ebc92eb1d39e1efe3761a7fb6cf588c25700c0a09c2b2468022ce9d2cab25d9711034cf3f3e536d95eba2e7a29918a38cfcf8737d8542fc66868c25d6b52e08f631d49efb9146b7da86cd0bd6e5e22749d135c0d899590a31f8339c86d861896140fcb3b949b32ed0240af925032f856e6fecbb81c040d92e1a73363746cba010ae6c2b18b8ad2eeae47cda4d9e47578c1e05e300cb2fb6f75c64b2c1715c88067aa270
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);


include("compat.inc");


if (description)
{
  script_id(50680);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/11/02");

  script_name(english:"Mac OS X Server Service List");
  script_summary(english:"Report list of installed services");

  script_set_attribute(
    attribute:"synopsis",
    value:
"This plugin enumerates services enabled on a Mac OS X Server host or
a host running OS X Server."
  );
  script_set_attribute(
    attribute:"description",
    value:
"By connecting to the remote host via SSH with the supplied
credentials, this plugin queries the Mac OS X Server administrative
daemon and enumerates services currently running on the system."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Review the list of services enabled and ensure that they agree with
your organization's acceptable use and security policies."
  );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:mac_os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


# Get the system version.
version = "";

# nb: OS X Server is an external app starting with 10.7.
if (ereg(pattern:"Mac OS X 10\.[0-6]([^0-9]|$)", string:os))
{
  cmd = '/usr/sbin/system_profiler SPSoftwareDataType';
  buf = exec_cmd(cmd:cmd);
  if (isnull(buf)) exit(1, "Failed to run '"+cmd+"'.");

  foreach line (split(buf, keep:FALSE))
  {
    match = eregmatch(pattern:"^ +System Version: (.+)$", string:line);
    if (match)
    {
      version = match[1];
      break;
    }
  }
  if (!strlen(version)) exit(1, "Failed to extract the System Version from the output of '"+cmd+"'.");

  # eg, "Mac OS X Server 10.6.8 (10K549)"
  if ("Mac OS X Server" >!< version) exit(0, "The host is not running Mac OS X Server.");
}
else 
{
  plist = "/Applications/Server.app/Contents/Info.plist";
  cmd = 
    'plutil -convert xml1 -o - \'' + plist + '\' | ' +
    'grep -A 1 CFBundleShortVersionString | ' +
    'tail -n 1 | ' +
    'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
  version = exec_cmd(cmd:cmd);
  if (!strlen(version)) audit(AUDIT_NOT_INST, "OS X Server");

  # eg, "2.1.1"
}


kb_base = 'MacOSX/Server/';
set_kb_item(name:kb_base+'Version', value:version);


# Get a list of services.
cmd = 'serveradmin list';
buf = exec_cmd(cmd:cmd);
if (!buf) exit(1, "Failed to run '"+cmd+"'.");

svcs = "";
foreach line (split(buf, keep:FALSE))
{
  if (
    ereg(pattern:"^[a-zA-Z0-9]+$", string:line) &&
    "accounts" != line &&
    "config" != line &&
    "filebrowser" != line &&
    "info" != line
  ) svcs += " " + line;
}
if (!svcs) exit(1, "'serveradmin list' output failed to list any services that can be queried: " + buf);


cmd = 'for s in ' + svcs + '; do serveradmin status $s; done';
buf = exec_cmd(cmd:cmd);
if (isnull(buf)) exit(1, "Failed to run '"+cmd+"'.");

info = "";
foreach line (split(buf, keep:FALSE))
{
  if (match = eregmatch(pattern:'^([^:]+):state *= *"?([^"]+)', string:line))
  {
    svc = match[1];
    status = match[2];
    set_kb_item(name:kb_base+svc+"/Status", value:status);
    info += '  - ' + svc + crap(data:" ", length:15-strlen(svc)) + ' : ' + status + '\n';
  }
}
if (!info) exit(1, "'serveradmin list' output does not contain any service info: " + buf);


# Report findings
if (report_verbosity > 0) security_note(port:0, extra:'\n'+info);
else security_note(0);
