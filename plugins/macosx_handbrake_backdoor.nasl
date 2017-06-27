#TRUSTED 4c9f2be8806a80ee842b0ab7b705884b35f4f98e941ab703620b16172474b50a31002032ec72ba4f2337dcebf9e0ac4f96fbd0f965d59db32ab9022ae95d70581f6bf99a15938199c262d4d7f401ac9a083f7ff3335ed8d99627ea73bf156d6433661b2af439861eb7f0696b51183022bc1fd26fc4ddd8932eeb7db829e9bb213b107e23ad9efc5eade658d4b15d26e20cc91e85ed16780492778a7d78ddbf383bab458838d2d318602e80ec92a93f9c016b33f2586a990c53a9b10dc380213a0ee540ed8156349bafdf35c0fde796c4ac6de1dbd64d188e054c560e3e1e87680fec1efc1aa73ff45228e300366f4710d99f23356b45099ff0b3d93d9710801c0d33c3ccfc75efc8cd5b100baec2c2e005f7eb6db5ed8e9d9bd0c586893b5f21dde2d69c7602f35b2d44f2194cb9e87c77d486861b8a186563bd0e051bbce514006e09f7d34a655496d0a23bc0f4921c797773409d8adf1271385bcf80d94e952ea2dba115e7417e0a4a16cf54a697adc5d867b89b04d045b3dc3e85f9c5a34ce315de5726a605d3d205217825a00beb8970098a6b120a1f4f571338e1767e813f3cb4dc77fe3eb45d09a416c6cb99139c5c03926b8fefd65baa013e0222f5d21399cda0fb3e8dccfe0fb2700a4ed74fdd39a3dca6507b65dd6775ff223223de15a05ab7ce9cbc22d3e639603f03ade297d841018634731b9551f858abe4af6d
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100128);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/11");

  script_osvdb_id(157221);

  script_name(english:"HandBrake OSX/Proton.B Trojan Backdoor (macOS)");
  script_summary(english:"Checks the HandBrake install for a trojanized application.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote macOS or Mac OS X host is
affected by a trojan.");
  script_set_attribute(attribute:"description", value:
"According to its binary checksum, the version of HandBrake installed
on the remote macOS or Mac OS X host is affected by the OSX/Proton.B
trojan backdoor. HandBrake was briefly distributed with the trojan due
to a compromised mirror hosting the software. An unauthenticated,
remote attacker can exploit this to exfiltrate sensitive information,
download malicious files, and execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://forum.handbrake.fr/viewtopic.php?f=33&t=36364");
  script_set_attribute(attribute:"solution", value:
"To remove the infected application, open the Terminal application and
run the following commands :

  - launchctl unload ~/Library/LaunchAgents/fr.handbrake.activity_agent.plist
  - rm -rf ~/Library/RenderFiles/activity_agent.app

Remove the proton.zip archive from the ~/Library/VideoFrameworks/
folder if it exists, and remove any HandBrake.app installs.
Additionally, it is strongly recommended to change all the passwords
that reside in your OSX KeyChain and browser password stores.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:handbrake:handbrake");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_handbrake_installed.nbin");
  script_require_keys("installed_sw/HandBrake", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit("Host/MacOSX/Version");

app_name = "HandBrake";
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

homes = get_users_homes();
if (empty_or_null(homes)) exit(1, "Failed to get list of users' home directories.");

vuln = FALSE;
report = "";

# Check HandBrake binary's checksum for infected checksum
cmd = 'shasum -a 1 ' + path + '/Contents/MacOS/HandBrake';
hash = exec_cmd(cmd:cmd);

if (hash && hash =~ 'a8ea82ee767091098b0e275a80d25d3bc79e0cea')
{
  vuln = TRUE;

  report +=
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  The version of HandBrake installed on the remote host is known' +
    '\n  to contain a trojan.';
}

# Check each user's home directory for files added for malware
# persistence:
#   ~/Library/RenderFiles/activity_agent.app
#   ~/Library/LaunchAgents/fr.handbrake.activity_agent.plist
foreach user (sort(keys(homes)))
{
  home = homes[user];
  if (home == "/var/empty" || home == "/dev/null") continue;

  cmd1 = strcat('ls "', home, '"/Library/RenderFiles');
  cmd2 = strcat('ls "', home, '"/Library/LaunchAgents');
  res = exec_cmds(cmds:make_list(cmd1, cmd2));

  if ("activity_agent.app" >< res[cmd1] ||
      "fr.handbrake.activity_agent.plist" >< res[cmd2])
  {
      vuln = TRUE;
      report += '\n\n  The following users have the infected files in their' +
                '\n  home directories :';
      if (strlen(res[cmd1]) && "activity_agent.app" >< res[cmd1])
      report += '\n    User : ' + user +
                '\n    File : ' + home + '/Library/RenderFiles/activity_agent.app';

      if (strlen(res[cmd2]) && "fr.handbrake.activity_agent.plist" >< res[cmd2])
      report += '\n    User : ' + user +
                '\n    File : ' + home + '/Library/LaunchAgents/fr.handbrake.activity_agent.plist';
  }
}

# Check for activity_agent in running processes
cmd = 'ps aux';
procs = exec_cmd(cmd:cmd);
if (strlen(procs) && "activity_agent" >< procs)
{
  vuln = TRUE;
  report += '\n\n  The activity_agent process is running on the system.';
}

if (vuln) security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
