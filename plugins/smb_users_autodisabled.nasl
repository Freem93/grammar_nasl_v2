#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10895);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2017/01/26 18:40:46 $");

 script_osvdb_id(752);

 script_name(english:"Microsoft Windows - Users Information : Automatically Disabled Accounts");
 script_summary(english:"Lists user accounts that have been automatically disabled.");

 script_set_attribute(attribute:"synopsis", value:
"At least one user account has been automatically disabled.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to list user accounts
that have been automatically disabled. These accounts may have been
disabled for security reasons or due to brute-force attack attempts.");
 script_set_attribute(attribute:"solution", value:
"Delete accounts that are no longer needed.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/15");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : User management");

 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");

 script_dependencies("smb_netusergetinfo.nasl");
 script_require_keys("SMB/Users/1");

 exit(0);
}


start_uid = get_kb_item("SMB/dom_users/start_uid");
if(!start_uid)
 start_uid = 1000;

end_uid = get_kb_item("SMB/dom_users/end_uid");
if(!end_uid)
 end_uid = start_uid + 200;


logins = "";
count = 1;
login = get_kb_item(string("SMB/Users/", count));
while(login)
{
 acb = get_kb_item(string("SMB/Users/", count, "/Info/ACB"));
 if(acb)
 {
  if(acb & 0x10){ # UF_LOCKOUT
  	logins = string(logins, "  - ", login, "\n");
    set_kb_item(name:"SMB/Users/AutoDisabled/"+count, value:login);
	}
 }
 count = count + 1;
 login = get_kb_item(string("SMB/Users/", count));
}

if(logins)
{
  if (max_index(split(logins)) == 1)
    report = "The following user account has been automatically disabled :\n";
  else
    report = "The following user accounts have been automatically disabled :\n";

  report = string(
    "\n",
    report,
    "\n",
    logins,
    "\n\n",
    "Note that, in addition to the Administrator, Guest, and Kerberos\n",
    "accounts, Nessus has enumerated only those domain users with UIDs\n",
    "between ", start_uid, " and ", end_uid, ". To use a different range, edit the scan policy\n",
    "and change the 'Start UID' and/or 'End UID' preferences for \n",
    "'SMB use domain SID to enumerate users' setting, and then re-run the scan.\n"
  );
  security_note(port:0, extra:report);
}
