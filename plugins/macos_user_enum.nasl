#TRUSTED 48712dcb6aa69604fda4e3b0a8f77e984594e125a266cecf27fddb534771622f191551b1fa94c93d415b510d13598d5cc1c6028711f4b5d84559703127a0b7e8a3cc85a677f7ecd3444955a284ee0361bbb8baaa938ec60cbf03ba88440aa668f9cafced6334148056b412c64d898c420561eff94ee681de483919df32b5a6a7f887b2738afad40e2ae6865e06fedb16a408a0db85c70bcfa9159cae871325c3f99f6bdb695f2d8723ba3e33e1a7d99aca1cd985f290bc4fc4b5be0ade19fa6514b733c2c2a855d77ea80ed63380794ea7c6bbc456965445a51533f59d581bf5776ac97a35f24784a30a7f85b57ff64c47183a54916d4eb3370ae5fafe964c4e0cb39fe212828a99f94b644220f5c37486de11e56e4df302f2bdc2a3781ea9ec0742667f68bad97c4730054ca0e63784ef7f066ecf2951d77a7d87a3b0e57854444046c520c8890406249d75efe8f6754132aad1112c9eac4818605c076c8077497fd780a4ee44458fee4be4f129d92d9f07bc381c253d9da8d377e507fbeb1f5bcaaacf172975b27a999755898505a4e9f8442c0fb29f6e654de1e1fd5ac1dc350bcffd1ddbb3f00d38f5c50c08cca08445d7ee92a0ff41e3f191d9a2f65b39f0e7cb0b1fe5cadea8d5258908af73bca5cb05e63a7bb966857e50046e75a6c594a12411856a4254525f1459bae8420285deac7af3a5af957effd36ad5f32cb7
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(95929);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/12/19");

  script_name(english:"macOS and Mac OS X User List Enumeration");
  script_summary(english:"Lists users on macOS and Mac OS hosts.");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate local users on the remote host.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to extract the member
list of the 'Admin' and 'Wheel' groups on the remote host. Members of
these groups have administrative access.");
  script_set_attribute(attribute:"solution", value:"None");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"macosx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running macOS or Mac OS X.");

cmd = "echo ; /usr/bin/dscl . -readall /Groups GroupMembership";
res_grp = exec_cmd(cmd:cmd);

cmd = "echo ; /usr/bin/dscl . -list /Users";
res_usr = exec_cmd(cmd:cmd);

if("RecordName" >!< res_grp || empty_or_null(res_usr)) exit(0, "Could not retrieve users or groups using dscl.");

###
# dscl returns groups/membership in the format, delimited by - :
# Users in GroupMembership delimited by spaces
# sometimes there are multiple group RecordNames, as is the case with lpadmin
#
# -
# GroupMembership: root _sophos casper JoeyBloggs temp cadmin
# RecordName: staff BUILTIN\Users
# - 
# GroupMembership: temp JoeyBloggs
# RecordName:
#  _lpadmin
#  lpadmin
#  BUILTIN\Print Operators
# -
# ...
###

# split into Recordname/Groupmembership blocks

if(!empty_or_null(res_grp)) grp_blk = split(res_grp, sep:"-", keep:FALSE);
pattern = 'GroupMembership: (.*)RecordName: (.*)';
users = make_array();

# For each group, add the group to a Users array entry for each
# user in group
foreach grp (grp_blk)
{
  if("GroupMembership" >!< grp) continue;

  match = eregmatch(pattern:pattern, string:join(split(grp, keep:FALSE)));

  # only grab the first group RecordNames if there are multiple
  firstname = split(match[2], sep:" ", keep:FALSE);

  # This is for instances like _lpadmin above, where there is a leading space
  # due to the new line in RecordName
  if(empty_or_null(firstname[0])) firstname = firstname[1];
  else firstname = firstname[0];

  # add group to groups list in user array
  foreach user (split(match[1], sep:" ", keep:FALSE))
  {
    if(empty_or_null(users[user])) users[user] = make_list(firstname);
    else users[user] = make_list(users[user], firstname);
  }
}

info = '';
info2 = '';
report = '';
svc = FALSE;
svc_nogroup = make_list();
set_kb_item(name:"Host/MacOSX/Users", value:res_usr);

foreach usr (split(res_usr,keep:FALSE))
{
  if(empty_or_null(usr)) continue;
  if(usr =~ "^_") svc = TRUE;

  if(!svc) info += '\n' + "User   : " + usr + '\n';
  else info2 += '\n' + "User   : " + usr +'\n';

  if(!empty_or_null(users[usr]))
  {
    if(!svc) info += "Groups : " + join(users[usr], sep:',\n         ') + '\n';
    else info2 += "Groups : " + join(users[usr], sep:',\n         ') + '\n';

    set_kb_item(name:"Host/MacOSX/Users/" + usr + "/Groups", value:join(users[usr], sep:'\n'));
  }
  
  svc = FALSE;
}

report = '\n' + "----------[ User Accounts ]----------" + '\n' + info + 
         '\n' +  "----------[ Service Accounts ]----------" + '\n' + info2;

security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
