#TRUSTED 4898552d6fdab5bcf93157b93c96d41bd4cf6157b827bf6e4fea6c0a5cb15a53c0a3428d3af80420a966bfbdb497ffdeec3b1d4708451c78ac701459cf9e445116931139a2e05b32afd89eda4b595f49d9f52a8a2470220a5b20183c28e1a7108ae1de01f3b7020dec39ce271ad67b3d9e6b8254bbfd4dd587365ee9b6ff6a534a709285a5143d9fcd0dddd1b2d6c41204f7afe13d9ec3d7e1685f710e682b33ad4e3105609ae59624944222703098d7c3265c3a82bf46654ddb2e9127d25cb84be443b0c061c33a81d915aee6ab11a098490e3895f3dec3914636cbd8c9868f17455189bfb2fa9cbc69011f9958ee8cc592c6c56df948c85e41aa3d0a56faacf6e95845625c1f468d0a5b1427fb12ff3d14e972f05bff1b42edfe1d2ec07c00636ab7d27134c2c05f42bc9a7981f5461d22a1f6fc5106df4098bb85655b95e70c4bf2a8a053ce5ea066bbe946d73a0ef6867b4c1fe938f7953dd5ed91d8a188ea3d9fd33154e1bd78579898153c5d29893b38a7635b1addf947b155d69c49c8fbd8a87184388fff6331911338714303df3d89b1a1a143cd537cdeae1c6813cc5ea94cf558c4d50703ffbec4a5a3df2f5004d85b915fef8f5d3a524be2bd102a6f65cfe7cdf9776c085f53700afab0d92c05c1f707d656a0e384488afb2f9e75ab82ea00764ea898f51cb232d94560c9b2aab795456fe8d9d79e9d3bf6e5f529
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70138);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/01/13");

  script_name(english:"IBM Tivoli Access Manager for e-Business / IBM Security Access Manager for Web Installed Components");
  script_summary(english:"Obtains components version information.");

  script_set_attribute(attribute:"synopsis", value:
"An access and authorization control management system is installed on
the remote host.");
  script_set_attribute(attribute:"description", value:
"IBM Security Access Manager for Web, formerly IBM Tivoli Access
Manager for e-Business, is installed on the remote host. The
application is an access and authentication control management system.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/access-mgr-web");
  # http://www-03.ibm.com/software/products/en/category/identity-access-management
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc66d382");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_access_manager_for_e-business");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("HostLevelChecks/proto", "Host/local_checks_enabled");

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
get_kb_item_or_exit("Host/local_checks_enabled");

# Do not run against Windows and some UNIX-like systems
# to avoid, among other things, Cisco, embedded devices,
# and so forth.
os = get_kb_item_or_exit('Host/OS');
os = tolower(os);
if (
  'linux' >!< os &&
  'aix' >!< os &&
  'solaris' >!< os
) audit(AUDIT_OS_NOT, "a supported OS");

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

# Check if pdversion exists
default_pdversion_path = "/opt/PolicyDirector/bin/pdversion";
output = info_send_cmd(cmd:"test -x " + default_pdversion_path + " && echo OK");
if ("OK" >!< output) audit(AUDIT_NOT_INST, 'IBM Access Manager for e-Business / IBM Security Access Manager');

# pdversion with no options only outputs the basic components, so
# need to specify all keys to get all info.
# Further, TAM and SAM support different values for '-key'
# so look for one, then the other and exit if neither is present
output = info_send_cmd(cmd:default_pdversion_path);

res = egrep(string:output, pattern:"IBM Tivoli Access Manager ");
if (strlen(res))
{
  # TAM is present
  component_keys = 'pdacld,pdauthadk,pdjrte,pdmgr,pdmgrprxy,pdrte,pdsms,pdweb,pdwebars,pdwebadk,pdwebrte,pdwpi,pdwsl,pdwpm,tivsecutl';
  app_name = 'IBM Tivoli Access Manager for e-Business';
}
else
{
  res = egrep(string:output, pattern:"Security Access Manager ");

  # If still nothing matching, neither TAM or SAM are installed; exit.
  if (!strlen(res))
    exit(1, "'" + default_pdversion_path + "' exists on the remote host, however, it provided no useful output.");

  # SAM is present
  component_keys = 'pdacld,pdauthadk,pdjrte,pdmgr,pdmgrprxy,pdrte,pdsms,pdweb,pdwebadk,pdwebars,pdwebpi,pdwebpi.apache,pdwebpi.ihs,pdwebrte,pdwpm,tivsecutl';
  app_name = 'Security Access Manager for Web';
}

appears_to_be_installed = TRUE;

# Call pdversion again, but with option to list all components
output = info_send_cmd(cmd:default_pdversion_path + " -key " + component_keys);
res = egrep(string:output, pattern:"(IBM Tivoli Access Manager|(IBM )?Security Access Manager|IBM (Tivoli )?Security Utilities)");
if (!strlen(res))
  exit(1, "'" + default_pdversion_path + "' exists on the remote host, however, it provided no useful output when using the '-key' option.");

res_lines = split(chomp(res));
info = "";
version = UNKNOWN_VER;
components = make_array();

# Components and versions output from pdversion are in the format :
# IBM Tivoli Access Manager Policy Server                6.1.0.0
# IBM Tivoli Access Manager Policy Proxy Server          Not Installed
#
# Note : for the newer Security Access Manager, the output lines
#        will contain 'Security Access Manager ' rather than
#        'IBM Tivoli Access Manager'.

# Get component and version from each line
foreach res_line (res_lines)
{
  if ("Not Installed" >< res_line) continue;

  matches = eregmatch(
    string:res_line,
    pattern:"^((IBM Tivoli Access Manager|(IBM )?Security Access Manager|IBM (Tivoli )?Security Utilities).*) ([0-9.]+)$"
  );
  if (isnull(matches)) continue;
  component = strip(matches[1]);
  component_ver = matches[5];

  # Use the version of the runtime component
  if (component == "IBM Tivoli Access Manager Runtime")
    version = component_ver;
  info += '\n' +
    '  Component : ' + component + '\n' +
    '  Version   : ' + component_ver + '\n';
  set_kb_item(name:'ibm/tivoli_access_manager_ebiz/components/'+component, value:component_ver);
  components[component] = component_ver;
}

if (appears_to_be_installed)
{
  set_kb_item(name:'ibm/tivoli_access_manager_ebiz/pdversion_path', value:default_pdversion_path);

  register_install(
    app_name:'IBM Access Manager for e-Business / IBM Security Access Manager',
    path:default_pdversion_path,
    version:version,
    cpe:"cpe:/a:ibm:tivoli_access_manager_for_e-business",
    extra:components
  );

  if (report_verbosity > 0)
  {
    if (info)
      report =
        '\n' + app_name + ' appears to be installed.' +
        '\nThe following file was used to discover the components listed' +
        '\nfurther below :' +
        '\n\n' +
        '  File : '+default_pdversion_path +
        '\n' +
        '\n' + info;
    else
      report =
        '\n' + app_name + ' appears to be installed,' +
        '\nhowever, no components or version information could be obtained.' +
        '\n' +
        '\nThe following file was used to discover the presence of' +
        '\n' + app_name + ' :' +
        '\n\n' +
        '  File : '+default_pdversion_path +
        '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
  exit(0);
}
audit(AUDIT_NOT_INST, 'IBM Tivoli Access Manager for e-Business / IBM Security Access Manager');
