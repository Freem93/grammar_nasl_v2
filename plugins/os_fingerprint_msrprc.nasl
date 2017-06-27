#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25248);
  script_version("$Revision: 1.39 $");
  script_cvs_date("$Date: 2016/05/09 20:07:11 $");

  script_name(english:"OS Identification : MSRPC");
  script_summary(english:"Determines the remote operating system.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the operating system by connecting to the
remote MSRPC server.");
  script_set_attribute(attribute:"description", value:
"This plugin attempts to identify the operating system type and version
by connecting to the remote Microsoft Remote Procedure Call (MSRPC)
server.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("netbios_name_get.nasl", "samba_detect.nasl");
  script_require_ports(139, 445, "Known/tcp/139", "Known/tcp/445");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");

function GetOSVersion ()
{
 local_var fid, data, rep, name;
 local_var platformid, csd, major, minor, build, ret, handle;

 fid = bind_pipe (pipe:"\spoolss", uuid:"12345678-1234-abcd-ef00-0123456789ab", vers:1);
 if (isnull (fid))
   return NULL;

 name = session_get_hostname();

 session_set_unicode (unicode:1);

 data = class_parameter (
   ref_id : 0x20000,
   name   : "\\"+get_host_ip()) +
            raw_dword (d:0) +
            raw_dword (d:0) +
            raw_dword (d:0) +

            raw_dword (d:MAXIMUM_ALLOWED) +
            raw_dword (d:2) +
            raw_dword (d:2) +
            raw_dword (d:0x20004) +

            raw_dword (d:0
 );

 data = dce_rpc_pipe_request (fid:fid, code:0x45, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 24))
   return NULL;

 ret = get_dword (blob:rep, pos:20);
 if (ret != 0)
   return NULL;

 handle = substr(rep, 0, 19);

 data = handle +
        class_name (name:"OSVersion") +
        raw_dword (d:500) ;

 data = dce_rpc_pipe_request (fid:fid, code:0x1A, data:data);
 if (!data)
   return NULL;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 516))
   return NULL;

 ret = get_dword (blob:rep, pos:strlen(rep)-4);
 if (ret != 0)
   return NULL;

 major = get_dword (blob:rep, pos:12);
 minor = get_dword (blob:rep, pos:16);
 build = get_dword (blob:rep, pos:20);
 platformid = get_dword (blob:rep, pos:24);
 csd = get_string (blob:rep, pos:28);
 if ( isnull(csd))
  return make_list(major,minor,build,platformid, "Service Pack 0");
 else
  return make_list(major,minor,build,platformid,csd);
}

function CheckXPtrkwks ()
{
 local_var fid, data, rep, name;
 local_var platformid, csd, major, minor, build, ret, handle;

 fid = bind_pipe (pipe:"\browser", uuid:"300f3532-38cc-11d0-a3f0-0020af6b0add", vers:1);
 if (isnull (fid))
   return NULL;

 name = session_get_hostname();

 session_set_unicode (unicode:1);

 data = raw_dword (d:0);

 data = dce_rpc_pipe_request (fid:fid, code:0x08, data:data);
 smb_close (fid:fid);

 if (!data)
   return 0;

 rep = dce_rpc_parse_response (fid:fid, data:data);
 if (!rep || (strlen(rep) != 4))
   return 2;

 return 1;
}

port = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

name = kb_smb_name();
session_init(socket:soc, hostname:name, smb2:FALSE);

ipc_failed = FALSE;

r = NetUseAdd(share:"IPC$");
if (r != 1) ipc_failed = TRUE;

confidence = 99;

os = NULL;
if (!isnull(Session[17]))
{
 os = Session[17];

 # Service pack is included for 2003 only
 if ("Windows Server 2003" >!< os)
 {
  if ("5.0" >< os || "4.0" >< os)
  {
   if ("5.0" >< os)
     os = "Microsoft Windows 2000";
   else
     os = "Microsoft Windows NT 4.0";

   if ( ipc_failed == FALSE )
   {
    info = NetServerGetInfo(level:101);
    if (!isnull(info))
    {
     flags = info[4];
     if (flags & 0x8000)
       os += " Server";
    }

    ret = GetOSVersion();
    if (!isnull(ret) && max_index(ret) == 5)
      os += " " + ret[4];
    else if (isnull(ret) && "5.0" >< os)
    {
      os += '\nNetApp';
      confidence = 75;
    }
   }
   else
   {
    if ("5.0" >< os)
    {
      os += '\nNetApp';
      confidence = 75;
    }
    else confidence = 80;
   }
  }
  else if ("5.1" >< os)
  {
   if ( ipc_failed == FALSE )
    ret = CheckXPtrkwks();
   else
   {
    ret = -1;
    confidence = 80;
   }

   if (ret == 1)
     os = string ("Microsoft Windows XP\nMicrosoft Windows XP Service Pack 1");
   else if (ret == 2)
   {
     os = 'Microsoft Windows XP Service Pack 2\nMicrosoft Windows XP Service Pack 3\nWindows XP for Embedded Systems';
   }
   else
     os = 'Microsoft Windows XP\nMicrosoft Windows XP for Embedded Systems';
  }
  else if ("Vista" >< os)
  {
   tos = os;
   os = "Microsoft Windows Vista";

   if ("Business" >< tos)
     os += " Business";
   else if ("Ultimate" >< tos)
     os += " Ultimate";
   else if ("Enterprise" >< tos)
     os += " Enterprise";
   else if ("Home" >< tos)
     os += " Home";
  }
  else if ("Windows Server 2008 R2 " >< os)
  {
    tos = os;
    os = "Microsoft Windows Server 2008 R2";
    if("Datacenter" >< tos)
      os += " Datacenter";
    else if("Enterprise" >< tos)
      os += " Enterprise";
    else if("Foundation" >< tos)
      os += " Foundation";
    else if("Standard" >< tos)
      os += " Standard";

    v = eregmatch(pattern:"Service Pack ([0-9]+)", string:tos);
    if (!isnull(v)) os += " Service Pack " + v[1];
  }
  else if ( "Windows Server (R) 2008 " >< os )
  {
    tos = os;
    os = "Microsoft Windows Server 2008";

    if("Datacenter" >< tos)
      os += " Datacenter";
    else if("Enterprise" >< tos)
      os += " Enterprise";
    else if("Foundation" >< tos)
      os += " Foundation";
    else if("Standard" >< tos)
      os += " Standard";

    v = eregmatch(pattern:"Service Pack ([0-9]+)", string:tos);
    if (!isnull(v)) os += " Service Pack " + v[1];
  }
  else if ( "Windows (R) Storage Server 2008 " >< os )
  {
    os = "Microsoft Windows Storage Server 2008";
  }
  else if ( "Windows 7 " >< os )
  {
    tos = os;
    os = "Microsoft Windows 7";

   if ("Ultimate" >< tos)
     os += " Ultimate";
   else if ("Enterprise" >< tos)
     os += " Enterprise";
   else if ("Home" >< tos)
     os += " Home";
    else if ("Professional" >< tos)
     os += " Professional";
   else if ("Starter" >< tos)
     os += " Starter";
  }
  else if ( "Windows 8 " >< os)
  {
    tos = os;
    os = "Microsoft Windows 8";
    if ("Enterprise" >< tos)
      os += " Enterprise";
    else if ("Pro" >< tos)
      os += " Pro";
  }
  else if ( "Windows 8.1 " >< os)
  {
    tos = os;
    os = "Microsoft Windows 8.1";
    if ("Enterprise" >< tos)
      os += " Enterprise";
    else if ("Pro" >< tos)
      os += " Pro";
  }
  else if ( "Windows Server 2012" >< os && "R2" >!< os)
  {
    tos = os;
    os = "Microsoft Windows Server 2012";
    if ("Standard" >< tos)
      os += " Standard";
    else if ("Datacenter" >< tos)
      os += " Datacenter";
    else if ("Essentials" >< tos)
      os += " Essentials";
    else if ("Foundation" >< tos)
      os += " Foundation";
  }
  else if ( "Windows Server 2012 R2" >< os)
  {
    tos = os;
    os = "Microsoft Windows Server 2012 R2";
    if ("Standard" >< tos)
      os += " Standard";
    else if ("Datacenter" >< tos)
      os += " Datacenter";
    else if ("Essentials" >< tos)
      os += " Essentials";
    else if ("Foundation" >< tos)
      os += " Foundation";
  }
  else if ( "Windows 10" >< os)
  {
    tos = os;
    os = "Microsoft Windows 10";
    if ("Home" >< tos)
      os += " Home";
    else if ("Pro" >< tos)
      os += " Pro";
    else if ("Education" >< tos)
      os += " Education";
    else if ("IoT" >< tos)
      os += " IoT Core";
    else if ("Enterprise Insider Preview" >< tos)
      os += " Enterprise Insider Preview";
    else if ("Enterprise" >< tos)
      os += " Enterprise";
  }
  else if ("Windows Embedded Standard 7" >< os)
  {
    v = eregmatch(pattern:"Service Pack ([0-9]+)", string:tos);
    os = "Microsoft Windows Embedded Standard 7";

    if (!isnull(v)) os += " Service Pack " + v[1];
  }
  else if ("OS400 " >< os)
  {
    os = 'IBM OS/400';
  }

  else os = NULL;
 }
 else
 {
  tos = os;

  os = "Microsoft Windows Server 2003";

  if ("Service Pack 1" >< tos)
    os += " Service Pack 1";
  else if ("Service Pack 2" >< tos)
    os += " Service Pack 2";
 }
}

if ( ipc_failed == FALSE ) NetUseDel();

if ( !isnull(os) && strlen(os) > 1 )
{
  if (
    "Windows" >< os &&
    get_kb_item("SMB/not_windows")
  ) exit(0, "The host is not running Windows but was fingerprinted as such.");

  set_kb_item(name:"Host/OS/MSRPC", value:os);
  # nb: don't consider lowering the confidence unless UDP port 137 could be accessed.
  if (get_kb_item("SMB/NetBIOS/137"))
  {
    macaddr = get_kb_item("SMB/mac_addr");
    if (isnull(macaddr) || macaddr == ":::::") confidence -= 30;
  }
  set_kb_item(name:"Host/OS/MSRPC/Confidence", value: confidence);
  set_kb_item(name:"Host/OS/MSRPC/Type", value:"general-purpose");
  exit(0);
}
