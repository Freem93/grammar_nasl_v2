#TRUSTED 355d0807df68ac6eeccabe67f0e5f810f8f6d12d7417d6ee4eb22db52bd73c3dfb1464616d30cc491d0223d45908ec6a3a9aacac19f761aa7e628ab20681a3df9b04477e451e2e818c2b0523ec1f6937cc5cfb55a43f3233e7d93166bf663c9fd6286ec4dddee9046946cf65aa7754fee7770a64e1baf831019b3a514ad2e3ecf23edb6a49daea134a3b8e024f839d5d03406f6141184508a2f185abb859b0420bf726f4b8d68cfbabbdf118f396aaa2388aa49d008a2878ab10526657876e5ff74bdb8d6fca6a8c00c77147dc30afd8f495277ad152488d18ce9eb899f2b88ee69e8b86e7daa79e4758b31a53abec924a3788d9cf6f12f9d88a9fbcedf88f90eaf4377248582198d896c65077c52c19173e54017814538b0d56d12586d42bc64a07332fd682d37b7e25a7500b00a13f9b5f470691e1316aa76c40cf90097096f5848620a593cd4fae082294c17485570480e8aef0d8fcdf866196647559dd9fec19b2985ec682bb8185c97e1c3c91cd5ca74bcf0600215d4274e30f6138596e426132e6f5eee7d3bbdde0b498e4e1a5df9f031674d4f510b88aa8841a1b0acb1f31e746399f96017980209f90580ffa8f4ab1db8b2fd41b4b59fe3a573f93bafcddef8aa3deeb9a352fc13f8c3ba4162ac1e30569692c1e3e0be74127bbde25397dae590847c089e66d3cc91b8ce2c9303582917d7c3e563735a3f50505b18b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69933);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/13");

  script_name(english:"DISA Security Readiness Review Scripts Detection");
  script_summary(english:"Detects DISA SRR Scripts.");

  script_set_attribute(attribute:"synopsis", value:"The remote host has a security auditing script present.");
  script_set_attribute(attribute:"description", value:
"The remote host has a copy of the DISA Security Readiness Review (SRR)
Scripts present.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("find_cmd.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# We may support other protocols here
if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF, 'pread');
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}

script_installs = make_array();

paths = '';

# by default only search certain home directory names
# unless the "Perform thorough tests" setting is enabled
home_dir = '[sS][rR][rR]';
if (thorough_tests) home_dir = '*';

# search only two levels deep and prune non-relevant
# results for speed
paths += '/home/' + home_dir + '/Start-SRR ';
paths += '/home/' + home_dir + '/*/Start-SRR ';
paths += '/export/home/' + home_dir + '/Start-SRR ';
paths += '/export/home/' + home_dir + '/*/Start-SRR ';

# search /root if the "Perform thorough tests" setting is enabled
if (thorough_tests)
{
  paths += '/root/Start-SRR ';
  paths += '/root/*/Start-SRR ';
}

res = find_cmd(path_patterns:make_list("*"), start:paths, exit_on_fail:TRUE);
res = res[1];

if (strlen(res) == 0) exit(0, 'No results returned from "find" command on remote host.');

foreach line (split(res, keep:FALSE))
{
  if (strlen(line) == 0) continue;

  if (
    line[0] != '/' ||
    "No such file or directory" >< line ||
    'stat() error' >< line || ('/home/' >!< line && '/root' >!< line)
  ) continue;

  # ignore lost and found directories
  if ("lost+found" >!< line) script_installs[line - 'Start-SRR'] = NULL;
}

if (max_index(keys(script_installs)) == 0) exit(0, "Did not find any DISA SRR scripts.");

found_install = FALSE;

# try to verify scripts and grab version
foreach dir (keys(script_installs))
{
  foreach test_file (make_list('sourcedVars', 'Start-SRR'))
  {
    res = info_send_cmd(cmd:'grep SRR_ProgramVersion= ' + dir + test_file);
    if (strlen(res) == 0) continue;

    # SRR_ProgramVersion="ProgramVersion=UNIX_51-29July2011"
    item = NULL;
    foreach line (split(res, keep:FALSE))
    {
      item = eregmatch(pattern:'SRR_ProgramVersion="[^=]+=([^"]+)"', string:line);
      if (!isnull(item)) break;
    }

    if (isnull(item)) continue;

    found_install = TRUE;
    script_installs[dir] = item[1];

    break;
  }
}

if (info_t == INFO_SSH) ssh_close_connection();

if (!found_install) exit(0, 'Unable to verify that DISA SRR scripts are present.');

install_num = 0;

set_kb_item(name:'DISA_SRR/Installed', value:TRUE);

foreach dir (keys(script_installs))
{
  version = script_installs[dir];
  if (isnull(version)) continue;

  report += '\n  Path    : ' + dir +
            '\n  Version : ' + version + '\n';

  set_kb_item(name:'DISA_SRR/' + install_num + '/Path', value:dir);
  set_kb_item(name:'DISA_SRR/' + install_num + '/Version', value:version);
  register_install(
    app_name:"DISA Security Readiness Review Scripts",
    path:dir,
    version:version);

  install_num ++;
}

set_kb_item(name:'DISA_SRR/num_instances', value:install_num);

if (report_verbosity > 0) security_note(port:0, extra:report);
else security_note(0);
