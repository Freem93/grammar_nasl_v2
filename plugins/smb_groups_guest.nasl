#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10907);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2017/02/02 16:12:18 $");

 script_name(english:"Microsoft Windows Guest Account Belongs to a Group");
 script_summary(english:"Checks the groups of guest.");

 script_set_attribute(attribute:"synopsis", value:
"The 'Guest' account has excessive privileges.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to determine that the
'Guest' user belongs to groups other than 'Guests' (RID 546) or
'Domain Guests' (RID 514). Guest users should not have any additional
privileges.");
 script_set_attribute(attribute:"solution", value:
"Edit the local or domain policy to restrict group membership for the
guest account.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/15");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : User management");

 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");

 script_dependencies("smb_sid2user.nasl", "smb_sid2localuser.nasl");
 script_require_ports (139,445);

 exit(0);
}

include ("audit.inc");
include ("misc_func.inc");
include ("smb_func.inc");
include ("obj.inc");

function get_sid_info(handle, sid)
{
  local_var names, sid_array, ret;

  # Lookup one sid
  sid_array = NULL;
  sid_array[0] = sid;

  ret = LsaLookupSid (handle:handle, sid_array:sid_array);
  if (isnull(ret)) return NULL;

  ret = parse_lsalookupsid (data:ret[0]);
  if(isnull(ret)) return NULL;

  sid['type']   = ret[0];
  sid['domain'] = ret[1];
  sid['name']   = ret[2];

  return sid;
}

function get_name (handle, sid, rid)
{
 local_var fsid, psid, name, type, user, names, tmp;

 if ( isnull(sid[1]) )
        return NULL;

 fsid = sid[0] + raw_byte (b: ord(sid[1])+1) + substr(sid,2,strlen(sid)-1) + raw_dword (d:rid);

 psid = NULL;
 psid[0] = fsid;

 names = LsaLookupSid (handle:handle, sid_array:psid);
 if (isnull(names))
   return NULL;

 name = names[0];
 tmp = parse_lsalookupsid (data:name);
 type = tmp[0];
 user = tmp[2];

 return user;
}

guest_dom = get_kb_item ("SMB/GuestAccount");
guest_host = get_kb_item("SMB/LocalGuestAccount");

host_sid   = get_kb_item("SMB/host_sid");
host_sid   = hex2raw2(s:host_sid);
domain_sid = get_kb_item("SMB/domain_sid");
domain_sid = hex2raw2(s:domain_sid);

# built-in domain sid
builtin_sid = raw_string (0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00);

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

if (guest_host)
  aliases = NetUserGetLocalGroups (user:guest_host, resolv:TRUE);

if (guest_dom)
  groups = NetUserGetGroups(user:guest_dom, resolv:TRUE);


handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel ();
  exit (0, "LsaOpenPolicy() failed");
}

# Get the name of Local Guests group
# Local Guests group is in Built-in domain
guests_host = get_name(handle: handle, sid: builtin_sid, rid: 546);

# Get the name of Domain Guests group
if(domain_sid)
  guests_dom = get_name(handle: handle, sid: domain_sid, rid: 514);

LsaClose (handle:handle);

#debugging
#display('local guest account:  ', guest_host, '\n');
#display('domain guest account: ', guest_dom, '\n');
#display('host_sid:   ', sid2string(sid:host_sid), '\n');
#display('domain_sid: ', sid2string(sid:domain_sid), '\n');
#display('Local Guests group:   ', guests_host, '\n');
#display('Domain Guests group:  ', guests_dom, '\n');
#display('local groups of the guest account:\n', obj_rep(aliases), '\n');
#display('global groups of the guest accounts:\n', obj_rep(groups), '\n');

none_groups = make_array(
  "NONE"   , TRUE, # English
  "NINGUNO", TRUE, # Spanish
  "KEIN"  , TRUE, # German
  "AUCUN"  , TRUE  # French
);

report = NULL;

header = FALSE;
if(!isnull(groups))
{
  foreach group ( groups )
  {
   if ( toupper(group) != toupper(guests_dom)
        && !none_groups[toupper(group)])
   {
    if (!header)
    {
      report = '\nDomain groups :\n\n';
      header = TRUE;
    }
    report += '   ' + group + '\n';
   }
  }
}

header = FALSE;
if(!isnull(aliases))
{
 foreach alias ( aliases )
 {
  if ( toupper(alias) != toupper(guests_host)
       && !none_groups[toupper(alias)])
  {
    if (!header)
    {
      report += '\nLocal groups :\n\n';
      header = TRUE;
    }
    report += '   ' + alias + '\n';
  }
 }
}

NetUseDel();

if ( strlen(report) )
{
 security_hole(port:0, extra:report);
}
