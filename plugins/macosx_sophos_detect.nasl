#TRUSTED 4b5a51a2005936732cae7597d830e962cb1f54e1e4e025335654da71922870f3f590f0ab549188baf668e6d78c4e069dcf6cb854cc93f6156b7ed9e6e03602300427f21f7f820705235b73f26c0846a3946ee1302300de4de098cac9679fd92fdc7e4813ca6f106b2b7edeae10be8b484726b07bca5f616d8149e209ac47128fe0b9633c7f76425672d5ab4d3b9d7dd0f49028319f2c3464f9e88744dfd296874ab5eb231a24b4c3fc5e331e1e9add3ca97f6ad476c7d15c5712b3c542c72bd80402b196a692b13fc1129731180c38890d160da92f0824993958884cb57df9c17795d2cfde7486315188ffbd18c06e67f1dd4eb820626b63ee7b804512c71940d88082c04ecd431c97716efdcac73042ab2475681e450ffa4073b7b6b70979edceabb7dd6a32dca87884f6a1f0d3342857bd2abff5733b3b8d9822f40e31d75ff1a03a256734b55cc71dbe3c22d78dc1a4f0c5be3684c629601a9d35f96d54a0774f7435385293068056f529adef75248bada8ae0f43bf27cd59be2699c90ba5fe21cfe43de66a35eda4474ad1ce81b0a2e7239279c2745b12c9f6ecf1bc5ba2f45a4d187766bd64780becc1ac7e2bfb231a1727c4ba89e18409a01af0305acb2e2187a39bb3e3559abe25923f8e9c2cc53e835eadb2076b9c336774e648911e7ae5413f92f0861c4b6b14881974d5cd53712ac712b375422907f94ed9d25c8c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54845);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/07/01");

  script_name(english:"Sophos Anti-Virus for Mac OS X Detection");
  script_summary(english:"Checks for Sophos Anti-Virus.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote Mac OS X host.");
  script_set_attribute(attribute:"description", value:
"Sophos Anti-Virus for Mac OS X, a commercial antivirus software
package, is installed on the remote host. Note that this plugin only
gathers information about the software, if it's installed. By itself,
it does not perform any security checks and does not issue a report.");
  script_set_attribute(attribute:"see_also", value:"https://www.sophos.com/en-us.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:sophos:sophos_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

global_var debug_level;

include("audit.inc");
include("datetime.inc");
include("global_settings.inc");
include("install_func.inc");
include("macosx_func.inc");
include("misc_func.inc");
include("ssh_func.inc");

plist = NULL;
regex = NULL;
sweep = "/usr/local/bin/sweep -v";
plutil = "plutil -convert xml1 -o - ";

paths = make_array(
          '/Library/Sophos Anti-Virus/product-info.plist', 'ProductVersion',
          '/Applications/Sophos Anti-Virus.app/Contents/Info.plist', 'CFBundleShortVersionString'
      );

order = make_list(
          '/Library/Sophos Anti-Virus/product-info.plist',
          '/Applications/Sophos Anti-Virus.app/Contents/Info.plist'
      );

foreach path (order)
{
  found = exec_cmd(cmd:'plutil \"' + path + '\"');
  if (!isnull(found) &&
      "file does not exist" >!< found)
  {
    plist = path;
    regex = paths[path];
    break;
  }
}

if ("Info.plist" >< path)
  sweep = "/usr/bin/sweep -v";

if (isnull(plist))
  audit(AUDIT_NOT_INST, "Sophos Anti-Virus");

cmd1 = string(
  plutil, "'", plist, "' | ",
  "grep -A 1 ", regex, "| ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);

# This value will return a string in format HH:MM:SS DD MON YYYY
av_log = "/Library/Logs/Sophos Anti-Virus.log";
cmd2 = string(
  "cat '", av_log, "' | ",
  "grep up-to-date | ",
  "tail -n 1 | ",
  'sed -e \'s/.*Software is up-to-date at //\''
);

vvf = "/Library/Sophos Anti-Virus/VDL/vvf.xml";
cmd3 = string(
  "cat '", vvf, "' | ",
  "grep VirusData | ", 
  'sed -e \'s/.*VirusData Version="//\' -e \'s/"//\' -e \'s/ .*//\''
);

cmd4 = string(
  "ps aux | grep -e 'SophosAutoUpdate' | grep -v 'grep'"
);

cmd5 = string(
  "ps aux | grep -e 'SophosAntiVirus' | grep -v 'grep'"
);

cmd6 = string(
  sweep, " | grep 'Engine version'"
);

results = exec_cmds(cmds:make_list(cmd1, cmd2, cmd3, cmd4, cmd5, cmd6));


if (isnull(results))
  audit(AUDIT_UNKNOWN_APP_VER, "Sophos Anti-Virus");

sophos_product_version = results[cmd1];

# If the version is <9, we don't have the signature date. <9 is unsupported.
if (sophos_product_version =~ "^[0-8]\.")
  sophos_threat_data = UNKNOWN_VER;
else
  sophos_threat_data = results[cmd3];

sophos_engine_version = split(results[cmd6], sep:":");
if (!empty_or_null(sophos_engine_version[1]))
  sophos_engine_version = strip(sophos_engine_version[1]);
else
 sophos_engine_version = UNKNOWN_VER;

sophos_auto_update_running = results[cmd4];
sophos_antivirus_running = results[cmd5];

date_match = eregmatch(string:results[cmd2], pattern:"^\d\d:\d\d:\d\d (\d+)\s+([A-Za-z]+)\s+(\d+)$");
if (!isnull(date_match))
{
  day = date_match[1];
  month = month_num_by_name(date_match[2], base:1);
  if (!isnull(month) && int(month) < 10)
    month = "0" + month;
  year = date_match[3];
  if (!isnull(year) && !isnull(month) && !isnull(day))
  {
    sophos_last_update_date = year + "-" + month + "-" + day;
  }
}

if (isnull(sophos_product_version) || isnull(sophos_threat_data))
  audit(AUDIT_UNKNOWN_APP_VER, "Sophos Anti-Virus");

if (isnull(sophos_engine_version))
  sophos_engine_version = 0;

pattern = "^[0-9][0-9.]+$";

if (sophos_product_version !~ pattern)
  audit(AUDIT_UNKNOWN_APP_VER, "the Sophos Anti-Virus product");

if (sophos_threat_data !~ pattern && sophos_product_version !~ "^[0-8]\.")
  audit(AUDIT_UNKNOWN_APP_VER, "the Sophos Anti-Virus threat data");

if (sophos_engine_version !~ pattern)
  audit(AUDIT_UNKNOWN_APP_VER, "the Sophos Anti-Virus engine");

date_pattern = "^\d{4}-\d{2}-\d{2}$";

if (sophos_last_update_date !~ date_pattern)
  sophos_last_update_date = "Unknown";

set_kb_item(name:"Antivirus/SophosOSX/installed", value:TRUE);
set_kb_item(name:"MacOSX/Sophos/Path", value:path);
set_kb_item(name:"MacOSX/Sophos/Version", value:sophos_product_version);
set_kb_item(name:"MacOSX/Sophos/ThreatDataVersion", value:sophos_threat_data);
set_kb_item(name:"MacOSX/Sophos/EngineVersion", value:sophos_engine_version);
set_kb_item(name:"MacOSX/Sophos/LastUpdateDate", value:sophos_last_update_date);

register_install(
  app_name:"Sophos Anti-Virus",
  path:path,
  version:sophos_product_version,
  extra:make_array(
    "ThreatDataVersion", sophos_threat_data,
    "EngineVersion", sophos_engine_version,
    "AutoUpdateRunning", sophos_auto_update_running,
    "AntiVirusRunning", sophos_antivirus_running,
    "LastUpdateDate", sophos_last_update_date)
);

if ("SophosAutoUpdate -d" >< sophos_auto_update_running)
  set_kb_item(name:"MacOSX/Sophos/AutoUpdateRunning", value:TRUE);
else
  set_kb_item(name:"MacOSX/Sophos/AutoUpdateRunning", value:FALSE);

if ("SophosAntiVirus -d" >< sophos_antivirus_running)
  set_kb_item(name:"MacOSX/Sophos/AntiVirusRunning", value:TRUE);
else
  set_kb_item(name:"MacOSX/Sophos/AntiVirusRunning", value:FALSE);
