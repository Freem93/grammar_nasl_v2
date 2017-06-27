#TRUSTED 8ad03d9d7740957a3f0a923ea1f61707cb3b95c018af806da549305b7368c0c05eb33b0f9376cfcd839cc8ad4e90e3567dbe3bb5b05474012b2533692c4142312d4d786dedd06e426f0c928f824be6548e28eab8d6f7b76eaa139c8f617bb78095e9bafa3c73a9e6938ae918c13aea22997607b787c03639e6dd523c8de0fafe9de2b4c125c7608399e0c66a95faa510f0c9498edc201d675dd2362d1b320dd8a0916523ab72447e95de020ee5ef572d012af185c842b6b3c84fd2ab2b13ffc1a9cb2fa6cfa0ebb634f31e75e037dcdf80909f8af561eb506b8cbde67500ae8b764043437129f8866c766e6306a6ce908d8fe89420c1d83ce0fcd49e69a3177cd99d91fc7126850d463c2ca325a83525338258fee86bccee48750c74b8e86f3f653ea07edee385753cc4f9fca863c91916163ff9ee74347690e206cd43e909a6c901581929093564c53e2a4bc7c2cc1fe65ad1fedd4431a917dbc3442beefb79b2f941f90ef5028b38d9dd877cc09d87f4d375ecf1a6205e9e1fc2adc397f98cedd735ab0ea1b430c5fab7882bfca494e10f1a6409695281f2e19d86bcf8310f3ca85c2d6cbc44aaac21bb5f4c533be50f76e3d8dbea44b9ce780cd443fc73ecca0bb058cecbded212779060a437ba6c4ab2eda0d17ee99326c264a5e66ae0d28dff27992c336ce475aa3a7cea96f6a74caa8cc243ac51bded29523ae4435b4a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69788);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/03/12");

  script_name(english:"Cisco Network Admission Control (NAC) Version");
  script_summary(english:"Obtains the version of the remote NAC");

  script_set_attribute(attribute:"synopsis", value:"It is possible to obtain the NAC version of the remote Cisco device.");
  script_set_attribute(attribute:"description", value:
"The remote host is a Cisco Network Admission Control (NAC) Manager.

It is possible to read the NAC version by connecting to the switch using
SSH.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:network_admission_control_manager_and_server_system_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("ssh_get_info.nasl");
  script_require_ports("Services/ssh", 22);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

include("ssh_func.inc");
include("hostlevel_funcs.inc");

##
# Saves the provided NAC version number in the KB, generates plugin output,
# and exits.
#
# @anonparam ver NAC version number
# @anonparam source protocol used to obtain the version
# @return NULL if 'ver' is NULL,
#         otherwise this function exits before it returns
##
function report_and_exit(ver, model, source)
{
  local_var report;

  set_kb_item(name:"Host/Cisco/NAC/Version", value:ver);

  replace_kb_item(name:"Host/Cisco/NAC", value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + ver;
    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# 1. SSH
# setup ssh tunnel
uname = get_kb_item_or_exit("Host/uname");
if ( "Linux" >!< uname ) exit(1, "The remote OS is not Linux-based");

sock_g = ssh_open_connection();
if (! sock_g) exit(1, "ssh_open_connection() failed.");
# issue command
nac_ssh = ssh_cmd(cmd:"cat /perfigo/build");
ssh_close_connection();

if (
  "Clean Access Manager" >< nac_ssh ||
  "Clean Access Server" >< nac_ssh ||
  "Network Admission Control" >< nac_ssh
)
{
  version = eregmatch(string:nac_ssh, pattern:"VERSION=([0-9][0-9.]+)");

  if (!isnull(version))
  {
    report_and_exit(ver:version[1], source:'SSH');
    # never reached
  }
}
exit(0, 'The Cisco NAC version is not available (the remote host may not be Cisco NAC).');
