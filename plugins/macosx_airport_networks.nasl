#TRUSTED 7a6e1d214d8be908c06d95d516e295a61dc53920fc208b79caf962443dcfd61b2be73e260946a24e61dec59bed63ef3319311809733bc982afbc5644d91d720235a7f10a792b0f93d0feb6c3fcec9ccb8c5e821073107c204b6a20f0d1906e33d310662e14ccb104f9e83cc2a42ffa953fed4ea28c80c1a6326cb9484b218b858c488e748b67fc4f3c7b56f69e504a9f5522da5090a71f9d98794fd005439cc59aeeef8821f6c3a4677ac3a421860bfa67523dd5597d609dbf61fe9cce841a50864dc1d1d197a2c68d28070e33c96cf1739a67ade277b53d48593d3f0d43f34f6c2aefedef238e6fe657bf226ed1b883c1071020d8ad1c66d8b5f7de0992dbecd03dd7777deb56384c8e19d0f4c7674047a2af941bfae3e5f55c025c43b4ae7ed9c1047c00836c0fc4c52d1aa4ea56d3b48042dc824cc79dd6c0e614a94f201f3dd6285414222f93824b1ffa4fbc419fd8042b058bdf863af83636650b1925967be40185f85e8f135c0ec484441b63a8bce49b94baa1209ee579549dbe3e87ff043959d7cd5e5ac842e4029d0a99f797f2e2df156781742f8df2fdb2dd6d3e8545ba727542e69128275aa76f80f01db9efb13cfc37c6534aef0127834e6693f7ee690365e1785531d94d0b0b61b7ce1bf7585ad0a8c717daf785852d1dea3b5a7039df78a6509874629adfe058052906a5413c970ea04e5d5585d4e439cbebcc
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(63340);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2012/12/27");

  script_name(english:"Mac OS X Wireless Networks List");
  script_summary(english:"Lists the Wi-Fi networks the remote host has connected to");

  script_set_attribute(attribute:"synopsis", value:"The remote host has connected to wireless networks in the past.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, it is possible to extract the list of
networks to which the remote host has connected in the past.");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of Wi-Fi networks is done in accordance to your
organization's acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

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

cmd = 'defaults read /Library/Preferences/SystemConfiguration/com.apple.airport.preferences RememberedNetworks | egrep "(SSIDString|LastConnected|SecurityType)"';

res = exec_cmd(cmd:cmd);
if ( "SSIDString =" >!< res ) exit(0, "Could not extract the list of Wi-Fi networks.");
array = split(res, keep:FALSE);
flag = 0;
foreach line ( array )
{
 if ( "LastConnected" >< line )
  date = str_replace(find:'"', replace:"", string:ereg_replace(pattern:".*LastConnected = (.*);$", string:line, replace:"\1"));
 else if ( "SecurityType" >< line )
 {
  security = str_replace(find:'"', replace:"", string:ereg_replace(pattern:".*SecurityType = (.*);$", string:line, replace:"\1"));
  flag = 1;
 }
 else if ( "SSIDString" >< line )
 {
  network = str_replace(find:'"', replace:"", string:ereg_replace(pattern:".*SSIDString = (.*);$", string:line, replace:"\1"));
  flag = 1;
 }

 if( (strlen(network) > 0 && strlen(security) > 0) ||
     (strlen(date) > 0 && strlen(network) > 0 && flag == 0 ) )  # In case there's no "SecurityType" associated to the remote network
 {
  report += '-  Network name : ' + network;
  if ( flag != 0 )
  {
   if ( strlen(date) ) report += '\n   Last connected : ' + date;
   else report += '\n   Last connected : N/A';
   date = NULL;
  }
  if ( strlen(security) )
  {
   report += '\n   Security: ' + security;
  }
  network = security = NULL;
  flag = 0;
  report += '\n\n';
 }
}

if ( strlen(report) > 0 ) security_note(port:0, extra:report);
