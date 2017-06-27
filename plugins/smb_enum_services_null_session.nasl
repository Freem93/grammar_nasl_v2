#
# (C) Tenable Network Security, Inc.
#

#
# Thanks to: Jean-Baptiste Marchand of Herve Schauer Consultants
#

include('compat.inc');

if (description)
{
  script_id(18585);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id("CVE-2005-2150");
  script_bugtraq_id(14093, 14177);
  script_osvdb_id(17859, 17860);

  script_name(english:"Microsoft Windows SMB Service Enumeration via \srvsvc");
  script_summary(english:"Enumerates the list of remote services");

  script_set_attribute(attribute:'synopsis', value:"The remote host allows null session enumeration of running services.");
  script_set_attribute(
    attribute:'description',
    value:
"This plugin connects to \srvsvc (instead of \svcctl) to enumerate the
list of services running on the remote host on top of a NULL session. 

An attacker may use this feature to gain better knowledge of the remote
host."
  );
  script_set_attribute(attribute:'solution', value:"Install the Update Rollup Package 1 (URP1) for Windows 2000 SP4.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:'see_also', value:"http://www.hsc.fr/ressources/presentations/null_sessions/");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_2000");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");

  script_dependencies("smb_enum_services.nasl", "smb_nativelanman.nasl");
  script_exclude_keys("SMB/not_windows");
  script_require_keys("SMB/transport", "SMB/name", "SMB/login", "SMB/password");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("smb_func.inc");


if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");


function OpenSCManager_SRVSVC (access_mode)
{
 local_var fid, ret, data, type, resp, rep, name, opnum;

 fid = bind_pipe (pipe:"\srvsvc", uuid:"367abb81-9844-35f1-ad32-98f038001003", vers:2);
 if (isnull (fid))
   return NULL;

 if (session_is_unicode() == 1)
   opnum = OPNUM_OPENSCMANAGERW;
 else
   opnum = OPNUM_OPENSCMANAGERA;

 data = raw_dword (d:0x0020000)                       + # ref_id
        class_name (name:"\\"+session_get_hostname()) +
        raw_dword (d:0)                               + # NULL database pointer
        raw_dword (d:access_mode) ;                     # Desired Access

 data = dce_rpc_pipe_request (fid:fid, code:opnum, data:data);
 if (!data)
   return NULL;

 # response structure :
 # Policy handle (20 bytes)
 # return code (dword)

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen (rep) != 24))
   return NULL;

 resp = get_dword (blob:rep, pos:20);
 if (resp != STATUS_SUCCESS)
   return NULL;

 ret = NULL;
 ret[0] = substr (rep, 0, 19);
 ret[1] = fid;
 ret[2] = 1;

 return ret;
}



os = get_kb_item("Host/OS/smb");
if ( "Windows 5.0" >!< os ) audit(AUDIT_OS_NOT, "Windows 2000");

port = kb_smb_transport();
if (!port) port = 139;
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

name = kb_smb_name();

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init (socket:soc,hostname:name);
ret = NetUseAdd (login:"", password:"", domain:"", share:"IPC$");
if (ret != 1)
{
 close(soc);
 audit(AUDIT_SHARE_FAIL, 'IPC$', code:0);
}


# Can we access \svcctl ?
pipe = "\svcctl";
handle = OpenSCManager(access_mode:SC_MANAGER_ENUMERATE_SERVICE);
if ( isnull(handle) )
{
 pipe = "\srvsvc";
 # Can we access \srvsvc ?
 handle = OpenSCManager_SRVSVC (access_mode:SC_MANAGER_ENUMERATE_SERVICE);
 if (isnull (handle))
 {
  NetUseDel();
  exit (0);
 }
}

list = EnumServicesStatus (handle:handle, type:SERVICE_WIN32, state:SERVICE_ACTIVE);

CloseServiceHandle (handle:handle);
NetUseDel ();

if (isnull (list))
  exit (1);

services = NULL;

foreach elem (list)
{
 parse = GetService (service:elem);
 services += parse[1] + " [ " + parse[0] + ' ] \n';
}


if (services)
{
 if ( ! get_kb_item("SMB/svcs") )
 	set_kb_item(name:"SMB/svcs", value:services);

 head = "
It was possible to enumerate the list of services running on the remote
host thru a NULL session, by connecting to " + pipe + "


Here is the list of services running on the remote host :
";

 services = head + services;
 security_warning(extra:services, port:port);
}
else audit(AUDIT_HOST_NOT, "affected");
