#
# (C) Tenable Network Security, Inc.
#
# @PREFERENCES@

include("compat.inc");

if (description)
{
 script_id(10399);
 script_version("$Revision: 1.75 $");
 script_cvs_date("$Date: 2017/02/02 16:12:18 $");

 script_cve_id("CVE-2000-1200");
 script_bugtraq_id(959);
 script_osvdb_id(714, 715);

 script_name(english:"SMB Use Domain SID to Enumerate Users");
 script_summary(english:"Enumerates users.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate domain users.");
 script_set_attribute(attribute:"description", value:
"Using the domain security identifier (SID), Nessus was able to
enumerate the domain users on the remote Windows system.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : User management");

 script_copyright(english:"This script is Copyright (C) 2000-2017 Tenable Network Security, Inc.");

 script_dependencies(
  "netbios_name_get.nasl",
  "smb_login.nasl",
  "smb_dom2sid.nasl"
 );
 script_require_keys(
  "SMB/transport",
  "SMB/name",
  "SMB/login",
  "SMB/password",
  "SMB/domain_sid"
 );
 script_require_ports(139, 445);
 script_add_preference(name:"Start UID : ", type:"entry", value:"1000");
 script_add_preference(name:"End UID : ", type:"entry", value:"1200");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


#---------------------------------------------------------#
# call LsaLookupSid with only one sid			  #
#---------------------------------------------------------#

function lookup_sid (handle, sid, rid)
{
 local_var fsid, psid, name, type, user, names, tmp;

 fsid = sid[0] + raw_byte (b: ord(sid[1])+1) + substr(sid,2,strlen(sid)-1) + raw_dword (d:rid);

 psid = NULL;
 psid[0] = fsid;

 names = LsaLookupSid (handle:handle, sid_array:psid);
 if (isnull(names))
   return NULL;

 name = names[0];
 # type, domain, user
 return  parse_lsalookupsid (data:name);
}


#---------------------------------------------------------#
# hexstr() to raw_string() conversion			  #
#---------------------------------------------------------#

function hexsid_to_rawsid(s)
{
 local_var i, j, ret;

 for(i=0;i<strlen(s);i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
  	j = int(s[i]);
  else
  	j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
  	j += int(s[i+1]);
  else
  	j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}

default_accounts = make_nested_array(
# rid                    display name                   specific kb item
  500, make_array('Name','Administrator account', 'KB','SMB/AdminName'),
  501, make_array('Name','Guest account',         'KB','SMB/GuestAccount'),
  502, make_array('Name','Kerberos account',      'KB','')
);
function report_user(name, rid, count, kb, extra)
{
  report += string('  - ', name, ' (id ' + rid);
  if (!empty_or_null(extra)) report += ', ' + extra;
  report += ')\n';
  set_kb_item(name:string("SMB/Users/", count), value:name);
  if (!empty_or_null(default_accounts[rid]) &&
      !empty_or_null(default_accounts[rid]['KB'])
  )
    set_kb_item(name:default_accounts[rid]['KB'], value:name);
}


port = kb_smb_transport();
if(!port)port = 139;
if(!get_port_state(port)) exit(0);
__start_uid = script_get_preference("Start UID : ");
__end_uid   = script_get_preference("End UID : ");

if(__end_uid < __start_uid)
{
 t  = __end_uid;
 __end_uid = __start_uid;
 __start_uid = t;
}

if(!__start_uid)__start_uid = 1000;
set_kb_item(name:"SMB/dom_users/start_uid", value: __start_uid);

if(!__end_uid)__end_uid = __start_uid + 200;
set_kb_item(name:"SMB/dom_users/end_uid", value: __end_uid);

__no_enum = string(get_kb_item("SMB/Users/0"));
if(__no_enum) exit(0);

__no_enum = string(get_kb_item("SMB/Users/1"));
if(__no_enum) exit(0);

report = NULL;

login = kb_smb_login();
pass  = kb_smb_password();
if(!login)login = "";
if(!pass)pass = "";

domain = kb_smb_domain();

# we need the SID of the domain
sid = get_kb_item_or_exit("SMB/domain_sid");

sid = hexsid_to_rawsid (s:sid);

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

ret = NetUseAdd (login:login, password:pass, domain:domain, share:"IPC$");
if ( ret != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel();
  audit(AUDIT_FN_FAIL, 'LsaOpenPolicy');
}

# enumerate users

num_users = 0;
set_kb_item(name:"SMB/Users/enumerated", value:TRUE);

foreach rid (keys(default_accounts))
{
  res = lookup_sid(handle:handle, sid:sid, rid:rid);
  if (isnull(res)) continue;
  type = res[0];
  name = res[2];
  # type 1 user
  if(type == 1 && name)
  {
    num_users += 1;
    acct = default_accounts[rid];
    report_user(
      name:name,
      rid:rid,
      count:num_users,
      kb:acct['KB'],
      extra:acct['Name']
    );
  }
}

#
# Retrieve the name of the users between __start_uid and __start_uid
#
mycounter = __start_uid - 1;
# pre-increment
while(++mycounter <= __end_uid)
{
  if (mycounter >= 500 && mycounter <= 502)
  {
    mycounter = 502; # will get incremented
    continue;
  }
  res = lookup_sid(handle:handle, sid:sid, rid:mycounter);
  if (isnull(res)) continue;
  type = res[0];
  name = res[2];
  if(type == 1 && name)
  {
    num_users += 1;
    report_user(name:name,rid:mycounter,count:num_users);
  }
}


LsaClose (handle:handle);
NetUseDel ();

if(num_users > 0)
{
 set_kb_item(name:"SMB/Users/count", value:num_users);
 report = string(
  "\n",
  report,
  "\n",
  "Note that, in addition to the Administrator, Guest, and Kerberos\n",
  "accounts, Nessus has enumerated only those domain users with IDs\n",
  "between ", __start_uid, " and ", __end_uid, ". To use a different range, edit the scan policy\n",
  "and change the 'Start UID' and/or 'End UID' preferences for this\n",
  "plugin, then re-run the scan.\n"
 );
 security_note(extra:report, port:port);
}
