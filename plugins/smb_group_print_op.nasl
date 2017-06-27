#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10905);
 script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");

 script_name(english:"Microsoft Windows 'Print Operators' Group User List");
 script_summary(english:"Lists users that are in special groups");

 script_set_attribute(attribute:"synopsis", value:"There is at least one user in the 'Print Operators' group.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, it is possible to extract the member
list of the 'Print Operators' group. Members of this group can manage
printers within a Windows Domain or shutdown a server.");
 script_set_attribute(attribute:"solution", value:"Verify that each member of the group should have this type of access.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : User management");
 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl");
 script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
 script_require_ports (139,445);
 exit(0);
}


include ("audit.inc");
include ("smb_func.inc");

sid = raw_string (0x01,0x02,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00,0x26,0x02,0x00,0x00);

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();


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
members = NetLocalGroupGetMembers (group:group[2]);

foreach member ( members )
{
  member = parse_lsalookupsid(data:member);
  info += string("  - ", member[1], "\\", member[2], " (", SID_TYPE[member[0]], ")\n");
}
NetUseDel();

if (info)
{
  if (max_index(split(info)) == 1)
    report = "The following user is a member";
  else
    report = "The following users are members";

  report = string(
    "\n",
    report, " of the 'Print Operators' group :\n",
    "\n",
    info
  );
  security_note(port:0, extra:report);
}
