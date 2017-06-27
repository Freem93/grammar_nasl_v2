#TRUSTED 9bf10ae6abd3be8e933ddc2853fbdafd1fd09fecc9f931b39d4776ea9dde514818dc92c98e3426bb4642a56c68d36c29f16ccfb8cc508a3c11f1ef5d0ed17623f7e2a1b61d27d9f53b647721e7bbe9b5ed50b1396f48ba8b803a88e1eb46c70495e710606907182bd6a97b8db592aea3e39436bc2b3ca795a2a52a71a9a5783658c8a4cc5a22abf3724fe02d53873a46f989b0aae1b15feb5ec310e2cb323660ef82e2aa6cfdf698cd6629ac81f6b6662698887cabec837a57c8ee480d885d136474e9f5614011a4ced0f0e5cdae8939018023c3a613352369393f255c8a0d8eecc4e5b517d40032756f20fbf780f863766d18e963522b92307f49dc47b3c7f0505939a2f0c4c150f00d5d535cb97abf9f92d67fa8a418019b865875039c530e94194800a1849245a6f7e4028bc4d3367281337caa6d8c8c9093aa9245643a462edb52f0d66d60120d72142c85a0a9dfe54848ec6ad57791802ad18098723d19701fb92029652e671c134cbfcec0588c9bf4f8b4b898912c83f3aa4ee82b9e60569405ad102f99e80f7c2e7a25547d5ad8df3cd9a6f5cfba846f491f0c938d29c652ad58077be568c62e1698abb8e1111592051101c8f35ab9e5a0073c30349713b21f5c7cb2c4c3cffe03b3b70aa485aadb6c9e8ab45fd9953bc4185bb9d29754cb635248bce799f20f48559994fadd4eebb99d00040fad25e9b2d46a506142
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(67244);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/09/15");

  script_name(english:"Cisco Prime Data Center Network Manager Installed (Linux)");
  script_summary(english:"Looks for dcnm files");

  script_set_attribute(attribute:"synopsis", value:"A network management system is installed on the remote Linux host.");
  script_set_attribute(attribute:"description", value:
"Cisco Prime Data Center Network Manager (DCNM) is installed on the
remote host. DCNM is used to manage virtualized data centers.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps9369/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:prime_data_center_network_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("HostLevelChecks/proto");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

proto = get_kb_item_or_exit('HostLevelChecks/proto');

installed = FALSE;

if (proto == 'local') info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

jboss_path = info_send_cmd(cmd:'grep ^JBOSS_HOME= /etc/init.d/jboss');
dcnm_path = NULL;

if (jboss_path =~ '^JBOSS_HOME=')
{
  jboss_path = split(jboss_path, sep:'=', keep:FALSE);
  jboss_path = jboss_path[1];

  # example path: /usr/local/cisco/dcm/jboss-4.2.2.GA
  # everything up to and including "cisco/" is configurable during installation
  # if "dcm" is not in the path, the init script was probably not created by the
  # DCNM installer
  if (jboss_path =~ '/dcm/jboss')
  {
    trailing_dir = strstr(jboss_path, '/jboss');
    dcnm_path = jboss_path - trailing_dir;
    ver_files = make_list(
      '/Uninstall_DCNM/installvariables.properties',
      '/dcnm/Uninstall_DCNM/installvariables.properties',
      '/dcnm/Uninstall_DCNM/InstallScript.iap_xml'
    );
  }
}

# if getting the install path failed for any reason,
# check the default installation directory for 4.x
if (isnull(dcnm_path))
{
  dcnm_path = '/DCNM';
  ver_files = make_list('/Uninstall_DCNM/installvariables.properties');
}

foreach ver_file (ver_files)
{
  file = dcnm_path + ver_file;

  # replace ' with '"'"' to prevent command injection
  file = str_replace(string:file, find:"'", replace:'\'"\'"\'');
  output = info_send_cmd(cmd:"grep '\(^\(PRODUCT_VERSION_NUMBER\|DCNM_SPEC_VER\|INSTALLER_TITLE\)=\|$PRODUCT_NAME$ [0-9.]\+\)' '" + file + "'");

  # if neither of the patterns match, it's likely the file doesn't exist
  # i.e., the command executed above did not get the product version
  ver = NULL;
  match = eregmatch(string:output, pattern:'PRODUCT_VERSION_NUMBER=(.+)');
  if (!isnull(match))
  {
    ver = match[1];
    match = eregmatch(string:output, pattern:'DCNM_SPEC_VER=(.+)');
    if (isnull(match)) match = eregmatch(string:output, pattern:"Data Center Network Manager\(DCNM\) ([\d.]+\([^)]+\))");

    if (isnull(match)) display_ver = ver;
    else display_ver = match[1];
  }
  else
  {
    match = eregmatch(string:output, pattern:"\$PRODUCT_NAME\$ ([\d.]+\(\d+\))");
    ver = match[1];
    display_ver = ver;
  }

  if (isnull(ver)) continue;

  # convert versions like 5.0(2) to 5.0.2.0
  # it's possible to get a version like this if the .properties file doesn't exist,
  # but the .xml file does
  match = eregmatch(string:ver, pattern:"^([\d.]+)\((\d+)(\w)?\)$");
  if (!empty_or_null(match))
  {
    # convert lowercase letters to numbers
    # a = 1, b = 2, et cetera
    revision = match[3];
    if (isnull(revision)) revision = '0';
    else revision = ord(revision) - 0x60;

    ver = strcat(match[1], '.', match[2], '.', revision);
  }

  installed = TRUE;

  register_install(
    app_name:'Cisco Prime DCNM',
    path:dcnm_path,
    version:ver,
    display_version: display_ver,
    cpe:"cpe:/a:cisco:prime_data_center_network_manager"
  );

  break;
}

if (installed) report_installs(port:0);
else audit(AUDIT_NOT_INST, 'Cisco Prime DCNM');
