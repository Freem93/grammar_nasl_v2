#TRUSTED af53571d33ec419b23bf73c10a2c8d575dbd4dda944994fd615146174a6e03cb251569a203b3d46c5f936983827a9a019934f3ac8162304b33321e382f63334555e39944358b2633aba108962cf13809f45c634053d01bdd204375709412e919d37ba2cf13a269596b8422be6a72ecacfbd4f62dfd963ce5606f0d3f72e4f4e4b73be47a4cd6a5ab6f44796ca11ebece273a38ef24a59475e3ab2647368d7a6685f58d30e5268619fca2a5ce4ff07b47f37addcf4f1ce280b9a33619e09294235b27f2bc63b1b14234c75957268571304c0506806ad86b8736d2410a107f69061bfcfa23c56bc56a3e8e78893c408a40fac0b439db22a259fd3acd9785afe48c27d5103b90fab71898c0c8c43256e7cb9089c58ccae71828e79d37a55fbe7dfe938f31262b7d3754fd66ab5ddf11bc0d6bd51da4f495f5475e285bc1e18d5abb269a82186712e78c1682971118899cbb5184336349c1e420770e3c3085d52babdc2a0a8314e010bbbc829de43a32cd59c56b777984b1e5885a18c8aa60eba40579ce76d90ad1ef65b82a028a5d5872d13f498ce30b2c3125a57c609ad952ba576a107b264e75ce13e3311c86505e2a5639f3e0e6ad68387c32b2a91926b40050c0160bbb8f7b4bd862a677c6ded8abb9a839306a1e7c0b617a919aee9caf22eff54c046965050a9fdbe32b15b1519d504f859c09aea9cdbfad4d73519348c30f
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70136);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2013/09/26");

  script_name(english:"Cisco Content Switching Module (CSM) Software Version");
  script_summary(english:"Gets the CSM version");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the CSM software version of the remote Cisco
device.");
  script_set_attribute(attribute:"description", value:
"The remote host has a Cisco Content Switching Module (CSM). 

It is possible to read the CSM software version by connecting to the
switch using SSH.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/hw/modules/ps2706/ps780/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:cisco_content_switching_module");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("ssh_func.inc");

# Verify that the target system is running Cisco IOS.
get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Require local checks be enabled.
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Try to extract the CSM software version from the "show module
# version" command.
cmd = "show module version";
sock_g = ssh_open_connection();
if (!sock_g) exit(0, "Failed to open an SSH connection.");
res = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
ssh_close_connection();

if (isnull(res)) exit(1, "Failed to execute '" + cmd + "' on the remote host.");

mods = make_list(
  "WS-X6066-SLB-APC",
  "WS-X6066-SLB-S-K9"
);

re = NULL;
foreach mod (mods)
{
  if (mod >< res)
  {
    # This regex needs to match the following example paragraphs:
    #
    # 4 4 WS-X6066-SLB-APC SAD093004BD Hw : 1.7
    # Fw :
    # Sw : 4.2(3a)
    #
    # 4 4 WS-X6066-SLB-S-K9 SAD093004BD Hw : 1.7
    # Fw :
    # Sw : 2.1(3)
    re = "\d\s+\d\s+" + mod + ".+[\r\n]Fw.+[\r\n]Sw\s*:\s*([0-9a-z][0-9a-z\.\(\)]+)";
    break;
  }
}

if (isnull(re)) exit(1, "Failed to find any CSM modules in the output of '" + cmd + "'.");

matches = eregmatch(string:res, pattern:re);
if (isnull(matches)) exit(1, "Failed to parse the version number of the CSM module on the remote host.");
ver = matches[1];

kb = "Host/Cisco/CSMSW";
set_kb_item(name:kb, value:TRUE);
set_kb_item(name:kb + "/Module", value:mod);
set_kb_item(name:kb + "/Version", value:ver);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Module  : ' + mod +
    '\n  Version : ' + ver +
    '\n';
}

security_note(port:0, extra:report);
