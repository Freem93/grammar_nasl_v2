#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10397);
 script_version("$Revision: 1.38 $");
 script_osvdb_id(300);
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");

 script_name(english:"Microsoft Windows SMB LanMan Pipe Server Listing Disclosure");
 script_summary(english:"Gets the list of remote host browse list");

 script_set_attribute(attribute:"synopsis", value:"It is possible to obtain network information.");
 script_set_attribute(attribute:"description", value:
"It was possible to obtain the browse list of the remote Windows system
by sending a request to the LANMAN pipe. The browse list is the list
of the nearest Windows systems of the remote host.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2000/05/09");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("netbios_name_get.nasl", "smb_login.nasl");
 script_require_keys("SMB/transport");
 script_require_ports(139, 445);
 exit(0);
}

include("audit.inc");
include("smb_func.inc");

function create_list (data)
{
 local_var comment, minor, major, list, name, server;

 list = NULL;

 foreach server (data)
 {
   name     = server[0];
   major    = server[1];
   minor    = server[2];
   comment  = server[4];

   if(comment)
    comment = " - " + substr(server,26,strlen(server)-1);

  list += name + string (" ( os : ", major, ".", minor, " )",comment,"\n");
 }

 return list;
}

port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();

if(!login)login = "";
if(!pass) pass = "";

dom = kb_smb_domain();
if (!dom) dom = "";

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

ret = NetUseAdd (login:login, password:pass, domain:dom, share:"IPC$");
if (ret != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, 'IPC$');
}

#
# Request the list of shares
#
servers = NetServerEnum (level:SERVER_INFO_101);
NetUseDel ();
if(!isnull(servers))
{
 # decode the list
 browse = create_list(data:servers);
 if(browse)
 {
  # display the list
  res = string("Here is the browse list of the remote host : \n\n");
  res = res + browse;
  report = string ("\n", res);

  security_note(port:port, extra:report);
  set_kb_item(name:"SMB/browse", value:browse);
 }
}
