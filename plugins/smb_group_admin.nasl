#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10902);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/08/24 16:23:37 $");

 script_name(english:"Microsoft Windows 'Administrators' Group User List");
 script_summary(english:"Lists users that are in special groups");

 script_set_attribute(attribute:"synopsis", value:"There is at least one user in the 'Administrators' group.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, it is possible to extract the member
list of the 'Administrators' group. Members of this group have
complete access to the remote system.");
 script_set_attribute(attribute:"solution", value:"Verify that each member of the group should have this type of access.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : User management");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports (139,445);
 exit(0);
}

include ("audit.inc");
include ("global_settings.inc");
include ("misc_func.inc");
include ("smb_func.inc");


global_var	info;

function generate_report(group, space, domain)
{
 local_var member, members, first;

 members = NetLocalGroupGetMembers (group:group, domain:domain);
 first = TRUE;

 foreach member ( members )
 {
  info += crap(data:" ", length:space);

  member = parse_lsalookupsid(data:member);
  if ( member[0] > 0 )
  {
   info += string("  - ", member[1], "\\", member[2], " (", SID_TYPE[member[0]], ")\n");
   if (member[0] == SidTypeGroup || member[0] == SidTypeAlias)
   {
      generate_report(group:member[2], space:space+4, domain:member[1]);
   }
  }
  else
   info += string("  - ", member[1], "\\", member[2], "\n");
 }
}

sid = raw_string (0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x20,0x02,0x00,0x00);

login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();
port = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

group = NULL;

lsa = LsaOpenPolicy (desired_access:0x20801);
if (!isnull(lsa))
{
 sids = NULL;
 sids[0] = sid;
 names = LsaLookupSid (handle:lsa, sid_array:sids);
 if (!isnull(names))
 {
  group = parse_lsalookupsid(data:names[0]);
 }

 LsaClose (handle:lsa);
}

if (isnull(group))
{
 NetUseDel();
 exit(0);
}

info = "";
generate_report(group:group[2], space:0, domain:group[1]);
NetUseDel();

if (info)
{
  if (max_index(split(info)) == 1)
    report = "The following user is a member";
  else
    report = "The following users are members";

  report = string(
    "\n",
    report, " of the 'Administrators' group :\n",
    "\n",
    info
  );

  security_note(port:port, extra:report);
}
