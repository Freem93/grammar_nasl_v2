#TRUSTED 9be9aa2b594d58b43812d5c3a77e5ce90a7fc4a4a9d6a7d8bee0e57352d5d3755a180cd087dbc1998b8f183456261bdb91f53c9c5232c03ca484745fa475bc5f240eaeb3b7e613aca178719567ed24b2dfa190db928b12dd533fd4d27376582abbf0e6d28637b6d58bb20cd3a60eeba08718a46721b17c2df6a9b22977c5187484a7fd437acf83796f4e03035180fde37303edc7f4f3da182928d5060b00873e506b23afa9f8fbfca3267bcb6577618f8f1fbb45d4621bda110391db2c141fa56370cfc37dc3091b6b092bdef6e9af83bcb6694054ae98acbaccf20c82f36ff209b90ada09beb80eaff14310e1eea6f014aaa1f569c512354c6bfff841433573182ccf8f02fd942b12b406d319c482aa1634b47bcd7bf1960cab517952e94013e1c926ddc1447bdd2e26aa44e26083a33cd3f532fd88ab445158d61b2f56ed1f2ed1bcdf73583bf18b25925c620778f23b45b23ed479d5e68e5b940e76b2b5e9948cd654041d30086111346e98788226a0a5725827ac5e0bbb1cd8af20884073b9a4a81a255358a7c5f78c4614ec0acdc4ddecd56f5ff14add4eac5d7107cbc16c808efec5dcf06a5ceaa1b94f148638b54b11ae896e2cc349da0981de695cb44b9598ae13923b1541a9d597f7fad814ada87e293141fe3c1ddfe6df546058a159a0a262b6047f546f5d211ee8d89d4e9ace7f155120e4db0473b12202792900
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69261);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/03/01");

  script_name(english:"Symantec Backup Exec Remote Agent for Linux and UNIX Servers (RALUS) Installed");
  script_summary(english:"Gets RALUS version from beremote");

  script_set_attribute(attribute:"synopsis", value:"The remote host contains a backup agent.");
  script_set_attribute(attribute:"description", value:
"Symantec Backup Exec Remote Agent for Linux and UNIX Servers (RALUS),
a backup agent for Linux and UNIX servers, is installed on the remote
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/products/data-backup-software");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:veritas_backup_exec");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("install_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

port = kb_ssh_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

ret = ssh_open_connection();
if (!ret) exit(1, 'ssh_open_connection() failed.');

path = '/opt/VRTSralus/bin/beremote';
cmd = "perl -pe 's/[^ -~]/\n/g' < " + path + ' | grep Version';
version = ssh_cmd(cmd:cmd);

if (!version)
{
  # Older versions can be fingerprinted via agent.be
  path = '/etc/bkupexec/agent.be';
  cmd = "perl -pe 's/[^ -~]/\n/g' <" + path + ' | grep Version';
  version = ssh_cmd(cmd:cmd);
}
ssh_close_connection();
if (!version) audit(AUDIT_NOT_INST, 'Symantec Backup Exec RALUS');

if ('VERITAS_Backup_Exec_File_Version=' >< version)
{
  version = strstr(version, 'VERITAS_Backup_Exec_File_Version=') - 'VERITAS_Backup_Exec_File_Version=';
  version = chomp(version);
}
else if ('Backup Exec -- Unix Agent' >< version)
{
  version = strstr(version, 'Backup Exec -- Unix Agent') - 'Backup Exec -- Unix Agent, Version ';
  version = chomp(version);
}
else exit(1, 'Failed to get the version number from ' + path + '.');

set_kb_item(name:"SSH/Symantec Backup Exec RALUS/Version", value:version);

register_install(
  app_name:'Symantec Backup Exec RALUS',
  path:path,
  version:version,
  cpe:"cpe:/a:symantec:veritas_backup_exec");

if (report_verbosity > 0)
{
  report =
    '\n  Path    : ' + path +
    '\n  Version : ' + version + '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
