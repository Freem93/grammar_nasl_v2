#TRUSTED 9c2012e6eb714a2d0d4f932c0884b7b083830e1557a58e41cab35a274482356382a02bd78623ffa362d6b9cd362b09c47daa813d817fd3146b9dac06792f25cd0df9187ad2ee3ad997320b8e05d5276893079de6e0048c4008e5eb17d64a04ef5a9af477a598a84edcd3e2f590556440f362bba5c114299830055d4c2dd574561b2275e715603a6141acf99116e614739d8a68eef8dde9bafd81ca98e6d835466f607796191b49bbecf39da99808c33b2a7f7e0de67d37d80479535ec8c0b770df8cef0cce88cf1f61ed2197c741b69e79a3a4a4cff12ed47c3d42cc5dfef0e322a9d376d981cd2c79a8c9f9eca3bf60a0d268bb2a7850861adc6bf84ffc8ca1db788f3919a8a6cffce1853944fd85ead425278912b0cc6cee8cc5e85e44ba881cce49334239e1221de50f38331f6feae01e9fda4796bf2b0cd2d10ca6cb47333562e3f55c76a6c9c677d71b58f20881f74aafa239607c090e8cb1bd2f7f7ef3b56d3bdbdd595b881d2ea167db79d081a5f9b159d36a966f9644d2ebb7250fc93ebee0a41bf0fd97397bd13c251f225b02b7039fe5bdd6f210f76f0a665b4bf82b9d7fda03e0db2a2fc1b6f9d85aca66d1d4e3b03e780fbde34a7d6d37cf17ea7b1c44564118226c2c9359f08290e9f1ac50071bac3c01aee41230acc0834b63cdcc88275b0503e7b458bd418bb80f478b5c292706dc834f93babe47291e64a3
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60019);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/01/26");

  script_name(english:"Mac OS X Admin Group User List");
  script_summary(english:"Lists users that are in special groups.");

  script_set_attribute(attribute:"synopsis", value:
"There is at least one user in the 'Admin' group.");
  script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to extract the member
list of the 'Admin' and 'Wheel' groups. Members of these groups have
administrative access to the remote system.");
  script_set_attribute(attribute:"solution", value:
"Verify that each member of the group should have this type of access.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

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
if (!os) exit(0, "The host does not appear to be running Mac OS X.");

cmd = "echo ; /usr/bin/dscl . -readall /Groups GroupMembership";

res = exec_cmd(cmd:cmd);

info = '';
info2 = '';

count = 0;
if (!isnull(res))
{
  blocks= split(res, sep:'-\n', keep:FALSE);
 
  pattern = '^(GroupMembership: (.*) )?RecordName: (.*)';
  foreach block (blocks)
  {
    block = str_replace(find:'\n', replace:' ', string:block);

    if ('RecordName: admin' >< block)
    {
      matches = eregmatch(string:block, pattern:pattern);
      if (!isnull(matches))
      {
        if (matches[2] != 'unknown')
        {
          foreach user (split(matches[2], sep:' ', keep:FALSE))
          {
            count += 1;
            set_kb_item(name:"SSH/LocalAdmins/Members/"+count, value:user);
            info += '  - ' + user + '\n';
          }
        }
      }
    }
    if ('RecordName: wheel' >< block)
    {
      matches = eregmatch(string:block, pattern:pattern);
      if (!isnull(matches))
      {
        if (matches[2] != 'unknown')
        {
          foreach user (split(matches[2], sep:' ', keep:FALSE))
          {
            count += 1;
            set_kb_item(name:"SSH/LocalAdmins/Members/"+count, value:user);
            info2 += '  - ' + user + '\n';
          }
        }
      }
    }
  }
}

if (info || info2)
{
  if (info)
  {
    if (max_index(split(info)) == 1)
      report = '\nThe following user is a member';
    else
      report = '\nThe following users are members';

    report =
      report + ' of the \'Admin\' group :\n' +
      chomp(info) + '\n';
  }

  if (info2)
  {
    if (max_index(split(info2)) == 1)
      report += 
        '\nThe following user is a member';
    else
      report += 
        '\nThe following users are members';

    report =
      report + ' of the \'Wheel\' group :\n' +
      chomp(info2) + '\n';
  }
      
  security_note(port:0, extra:report);
}
else exit(0, 'No members of the \'Admin\' or \'Wheel\' groups were found on the remote host.');
