#
# (C) Tenable Network Security, Inc.
#
# @PREFERENCES@

include("compat.inc");

if (description)
{
 script_id(56211);
 script_version("$Revision: 1.6 $");
 script_cvs_date("$Date: 2017/01/30 15:10:03 $");

 script_cve_id("CVE-2000-1200");
 script_bugtraq_id(959);
 script_osvdb_id(714, 715);

 script_name(english:"SMB Use Host SID to Enumerate Local Users Without Credentials");
 script_summary(english:"Enumerates local users, without credentials.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate local users, without credentials.");
 script_set_attribute(attribute:"description", value:
"Using the host security identifier (SID), Nessus was able to enumerate
local users on the remote Windows system, without credentials.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/04/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : User management");

 script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

 script_dependencies(
  "netbios_name_get.nasl",
  "smb_login.nasl",
  "smb_host2sid_null_session.nasl"
 );
 script_require_keys(
  "SMB/transport",
  "SMB/name",
  "SMB/null_session/host_sid"
 );
 script_require_ports(139, 445);

 exit(0);
}


include("audit.inc");
include("smb_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

#---------------------------------------------------------#
# call LsaLookupSid with only one sid			  #
#---------------------------------------------------------#

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


port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

if(!__start_uid)__start_uid = 1000;

if(!__end_uid)__end_uid = __start_uid + 200;


# we need the  netbios name of the host
name = kb_smb_name();
if(!login)login = "";
if(!pass)pass = "";
domain = "";


# we need the SID of the domain
sid = get_kb_item("SMB/null_session/host_sid");

if(!sid)exit(0);

sid = hex2raw2 (s:sid);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:login, password:pass, domain:domain, share:"IPC$");
if (ret != 1)
{
 close(soc);
 audit(AUDIT_SHARE_FAIL, "IPC$");
}

handle = LsaOpenPolicy (desired_access:0x20801);
if (isnull(handle))
{
  NetUseDel ();
  exit (0);
}

num_users = 0;
report = "";

kb_prefix = "SMB/LocalUsers/NullSession/";
n = get_name(handle:handle, sid:sid, rid:500);
if(n)
{
 num_users = num_users + 1;
 report = report + string("  - ", n, " (id 500, Administrator account)\n");
 set_kb_item(name:kb_prefix+num_users, value:n);
}


n = get_name(handle:handle, sid:sid, rid:501);
if(n)
{
  report = report + string("  - ", n, " (id 501, Guest account)\n");
  num_users = num_users + 1;
  set_kb_item(name:kb_prefix+num_users, value:n);
}

#
# Retrieve the name of the users between __start_uid and __start_uid
#
mycounter = __start_uid;
while(1)
{
 n = get_name(handle:handle, sid:sid, rid:mycounter);
 if(n && mycounter != 500 && mycounter != 501)
 {
  report = report + string("  - ", n, " (id ", mycounter, ")\n");
  num_users = num_users + 1;
  set_kb_item(name:kb_prefix+num_users, value:n);
 }

 mycounter++;
 if(mycounter > __end_uid)break;
}


LsaClose (handle:handle);
NetUseDel ();

if(num_users > 0)
{
  set_kb_item(name:kb_prefix+"count", value:num_users);
 report = string(
  "\n",
  report,
  "\n"
 );
 security_warning(extra:report, port:port);
}
