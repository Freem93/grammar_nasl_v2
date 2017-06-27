#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10910);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2017/01/26 18:40:46 $");

 script_name(english:"Microsoft Windows Local User Information");
 script_summary(english:"Implements NetUserGetInfo().");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to retrieve local user information.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was able to retrieve
information for each local user.

Note that this plugin itself does not issue a report and only serves
to store information about each local user in the KB for further
checks.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2002/03/17");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : User management");

 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");

 script_dependencies(
  "netbios_name_get.nasl",
  "smb_login.nasl",
  "smb_sid2localuser.nasl",
  "smb_host2sid.nasl"
 );
 script_require_keys(
  "SMB/transport",
  "SMB/name",
  "SMB/login",
  "SMB/password",
  "SMB/LocalUsers/enumerated",
  "SMB/host_sid"
 );
 script_require_ports(139, 445);

 exit(0);
}

include("audit.inc");
include("smb_func.inc");

# script compatibility
function _ExtractTime(buffer)
{
 return(string(      hex(ord(buffer[7])), "-",
                     hex(ord(buffer[6])), "-",
                     hex(ord(buffer[5])), "-",
                     hex(ord(buffer[4])), "-",
                     hex(ord(buffer[3])), "-",
                     hex(ord(buffer[2])), "-",
                     hex(ord(buffer[1])), "-",
                     hex(ord(buffer[0]))));
}

if (get_kb_item("SMB/samba")) audit(AUDIT_OS_NOT, "Windows");

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

count = 1;
login = string(get_kb_item(string("SMB/LocalUsers/", count)));
while(login)
{
 info = NetUserGetInfo (user:login);
 if (!isnull (info))
 {
  if(! isnull(info[0]))
  {
    name = string("SMB/LocalUsers/", count, "/Info/LogonTime");
    replace_kb_item(name:name, value:info[0]);
  }

  if(! isnull(info[1]))
  {
    name = string("SMB/LocalUsers/", count, "/Info/LogoffTime");
    replace_kb_item(name:name, value:info[1]);
  }

  if(! isnull(info[2]))
  {
    name = string("SMB/LocalUsers/", count, "/Info/PassLastSet");
    replace_kb_item(name:name, value:info[2]);
  }

  if(! isnull(info[3]))
  {
    name = string("SMB/LocalUsers/", count, "/Info/KickoffTime");
    replace_kb_item(name:name, value:info[3]);
  }

  if(! isnull(info[4]))
  {
    name = string("SMB/LocalUsers/", count, "/Info/PassCanChange");
    replace_kb_item(name:name, value:info[4]);
  }

  if(! isnull(info[5]))
  {
    name = string("SMB/LocalUsers/", count, "/Info/PassMustChange");
    replace_kb_item(name:name, value:info[5]);
  }

  if(! isnull(info[6]))
  {
    name = string("SMB/LocalUsers/", count, "/Info/ACB");
    replace_kb_item(name:name, value:int(info[6]));

  }
 }

 count = count + 1;
 login = string(get_kb_item(string("SMB/LocalUsers/", count)));
}

NetUseDel ();
