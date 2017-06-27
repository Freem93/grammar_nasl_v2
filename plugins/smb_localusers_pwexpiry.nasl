#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10916);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2017/01/26 18:40:46 $");

 script_osvdb_id(755);

 script_name(english:"Microsoft Windows - Local Users Information : Passwords Never Expire");
 script_summary(english:"Lists local users whose passwords never expire.");

 script_set_attribute(attribute:"synopsis", value:
"At least one local user has a password that never expires.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to list local users
that are enabled and whose passwords never expire.");
 script_set_attribute(attribute:"solution", value:
"Allow or require users to change their passwords regularly.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/17");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : User management");

 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");

 script_dependencies("smb_netusergetinfo_local.nasl");
 script_require_keys("SMB/LocalUsers/1");

 exit(0);
}


start_uid = get_kb_item("SMB/local_users/start_uid");
if(!start_uid)
 start_uid = 1000;

end_uid = get_kb_item("SMB/local_users/end_uid");
if(!end_uid)
 end_uid = start_uid + 200;

logins = "";
count = 1;
login = get_kb_item(string("SMB/LocalUsers/", count));
while(login)
{
 disabled = FALSE;
 acb = get_kb_item(string("SMB/LocalUsers/", count, "/Info/ACB"));
 if (acb)
 {
  # UF_ACCOUNTDISABLE
  if (acb & 0x0002) disabled = TRUE;
 }
 #UF_DONT_EXPIRE_PASSWD
 if ((acb & 0x10000) && !disabled && login !~ "\$$")
 {
  logins = string(logins, "  - ", login, "\n");
  set_kb_item(name:"SMB/LocalUsers/PwNeverExpires/"+count, value:login);
 }
 count = count + 1;
 login = get_kb_item(string("SMB/LocalUsers/", count));
}

if(logins)
{
  if (max_index(split(logins)) == 1)
    report = "The following local user has a password that never expires :\n";
  else
    report = "The following local users have passwords that never expire :\n";

  report = string(
    "\n",
    report,
    "\n",
    logins,
   "\n\n",
   "Note that, in addition to the Administrator and Guest accounts, Nessus\n",
   "has only checked for local users with UIDs between ", start_uid, " and ", end_uid, ".\n",
   "To use a different range, edit the scan policy and change the 'Start\n",
   "UID' and/or 'End UID' preferences for this plugin, then re-run the\n",
   "scan.\n"
  );
  security_note(port:0, extra:report);
}
