#TRUSTED 060da40d8df124a37ab09c85de213f32302e844eac6846c6c057effaf1603f9e01333aa276f1d32941e7fe3e1c82ca0c4af15935dfc1e2d5fec0588b8eef92a33e1f752a2f9e1c4c61974dd70185f36624da253c2a91f0d12b4683f72463412ec5018ecd3a758870eca6eea73c877469913260171b5c0c87fe7668674b60a80d5c63f562aad89ba1df84e166b7cb28ac8ad9cce8587dcddfd6053890d8947598653b260f39a9c68075ec36c4ce25eb9c118630fe59fcddb3a45651f8e9a5d36ab08ec75ab4377bce48c690cfd854964829f3f1efad36e001fdc4aa6e54b632b0dbbeb6e23eeed66498caad28a19a2492935402ad48c298389c02a967712174660a5ec9c342b962b6712aec2fbd25825959362db556523baa72b704014e48d6c59e69f55195f1fe6314fbf2117a81f79f8cc733d389da869ea20950911466c2f6265dc2c81950088f02ac0a11cef130d26ec8f3b02f39fd57309da4ca24f0aa8fcd0198435983bf1e5b0881d9310e70d2e5461f0439842c0bee8f035662b9b0c3c9e45c2afd9b80f54bcf83e8b476e6ad1ebfb703a20d36481eb3f637305d1c5fdc96a757e78a5eda8e57cc2f6c47c2a5601e524b87f92a8945036bfccb1c336187cd60d5fe6d8f6d652e3f24e461fc8b5108e44d7730a9fae22a4de6fbac605a325967080da939b9657ab36ab547450aa55a8548f81dd3ae9efaacbe6cfb9920
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(95928);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/12/19");

  script_name(english:"Linux User List Enumeration");
  script_summary(english:"Lists users on Linux host.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate local users and groups on the remote
host.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to enumerate the local
users and groups on the remote host.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("agent.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

# Decide transport for testing
if (islocalhost())
{
  if ( ! defined_func("pread") ) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

cmd = "cat /etc/passwd";
etcp = info_send_cmd(cmd:cmd);

cmd = "cat /etc/group";
etcg = info_send_cmd(cmd:cmd);

cmd = "cat /etc/login.defs";
etcl = info_send_cmd(cmd:cmd);

if("Permission denied" >< etcp || empty_or_null(etcp)) exit(0, "Could not read /etc/passwd.");

checkuid = FALSE;
if("UID_MIN" >< etcl){
  match = eregmatch(pattern:"UID_MIN\s+(\d+)\s+UID_MAX\s+(\d+)", string:join(split(etcl,keep:FALSE),sep:" "));
  if(!empty_or_null(match))
  {
    uid_min = int(match[1]);
    uid_max = int(match[2]);
  }
  checkuid = TRUE;
}
users = make_array();
groups = make_array();

foreach grp (split(etcg, keep:FALSE))
{
  if(grp !~ "^[^:]+:[^:]*:[^:]*:[^:]*$") continue;
  grp = split(grp, sep:":", keep:FALSE);
  groups[grp[2]] = grp[0];
  foreach user (split(grp[3], sep:"," , keep:FALSE))
  {
    if(empty_or_null(users[user])) users[user] = make_array(grp[0], TRUE);
    else users[user][grp[0]] = TRUE;
  }
}

report = '';
report_usr = '';
report_sys = '';
usr_acct = FALSE;

foreach line (split(etcp, keep:FALSE))
{
  if(line !~ "^[^:]+:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*$") continue;
  usr = split(line, sep:":", keep:FALSE);
  uid = int(usr[2]);
  home = usr[5];
  shell = usr[6];
  gid = usr[3];
  usr = usr[0];
  if(checkuid && uid >= uid_min && uid <= uid_max) usr_acct = TRUE;
  # add default group in case it wasn't already added
  if(empty_or_null(users[usr])) users[usr] = make_array(groups[gid], TRUE);
  else users[usr][groups[gid]] = TRUE;

  if(checkuid)
  {
    if(usr_acct)
    {
      report_usr += '\n';
      report_usr += join( "User         : " + usr, 
                          "Home folder  : " + home, 
                          "Start script : " + shell,
                          "Groups       : " + join(keys(users[usr]), sep:'\n               '),
                          sep:'\n');
      report_usr += '\n';
    }
    else
    {
      report_sys += '\n'; 
      report_sys += join( "User         : " + usr, 
                          "Home folder  : " + home, 
                          "Start script : " + shell,
                          "Groups       : " + join(keys(users[usr]), sep:'\n               '),
                          sep:'\n');
      report_sys += '\n';
    }

  }
  else
  {
    report += '\n';
    report += join( "User         : " + usr, 
                  "Home folder  : " + home, 
                  "Start script : " + shell,
                  "Groups       : " + join(keys(users[usr]), sep:'\n               '),
                  sep:'\n');
    report += '\n';   
  }
  if(!empty_or_null(users[usr]))
    set_kb_item(name:"Host/Users/"+usr+"/Groups", value:join(keys(users[usr]), sep:'\n'));

}
set_kb_item(name:"Host/Users", value:join(keys(users), sep:'\n'));

if(checkuid) report = '\n' + 
                      "----------[ User Accounts ]----------" + 
                      '\n' +
                      report_usr +
                      '\n' +
                      "----------[ System Accounts ]----------" + 
                      '\n' +
                      report_sys +
                      '\n';

security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
