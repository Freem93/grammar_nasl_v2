#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10150);
 script_version("$Revision: 1.82 $");
 script_cvs_date("$Date: 2016/12/28 01:10:44 $");

 script_name(english:"Windows NetBIOS / SMB Remote Host Information Disclosure");
 script_summary(english:"Using NetBIOS or SMB to retrieve information from a Windows host.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to obtain the network name of the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host is listening on UDP port 137 or TCP port 445, and
replies to NetBIOS nbtscan or SMB requests.

Note that this plugin gathers information to be used in other plugins,
but does not itself generate a report.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/10/12");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("cifs445.nasl", "dcetest.nasl");
 exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');

function will_scan_port()
{
 local_var target;
 local_var pref;
 local_var port;
 local_var i;


 target = _FCT_ANON_ARGS[0];
 if ( NESSUS_VERSION =~ "^3\." ) return TRUE; # Bug in older versions
 if ( isnull(target) ) return TRUE;

 pref = get_preference("unscanned_closed");
 if ( isnull(pref) || pref != "yes" ) return TRUE;

 for ( i = 0 ; TRUE ; i ++ )
 {
 port = scanner_get_port(i);
 if ( isnull(port) ) break;
 if ( port == target ) return TRUE;
 if ( port >  target ) break;
 }

 return FALSE;
}

global_var wildcard, unique_desc, group_desc, nbname, nbgroup, messenger_count;

if ( !will_scan_port(445) && !will_scan_port(139) && !will_scan_port(137) ) exit(0, "Ports 137, 139 and 445 are marked as non-scannable.");

nbname = nbgroup = NULL;
messenger_count = 0;

wildcard = "*" + raw_string (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

unique_desc[0x00] = "Computer name";
unique_desc[0x01] = "Messenger Service";
unique_desc[0x03] = "Messenger Service";
unique_desc[0x06] = "RAS Server Service";
unique_desc[0x1B] = "Domain Master Browser";
unique_desc[0x1D] = "Master Browser";
unique_desc[0x1F] = "NetDDE Service";
unique_desc[0x20] = "File Server Service";
unique_desc[0x21] = "Ras Client Service";
unique_desc[0x22] = "Microsoft Exchange Interchange";
unique_desc[0x23] = "Microsoft Exchange Store";
unique_desc[0x24] = "Microsoft Exchange Directory";
unique_desc[0x2B] = "Lotus Notes Server Service";
unique_desc[0x30] = "Modem Sharing Server Service";
unique_desc[0x31] = "Modem Sharing Client Service";
unique_desc[0x43] = "SMS Client Remote Control";
unique_desc[0x44] = "SMS Administrators Remote Control Tool";
unique_desc[0x45] = "SMS Clients Remote Chat";
unique_desc[0x46] = "SMS Clients Remote Transfer";
unique_desc[0x4C] = "DEC Pathworks TCPIP service on Windows NT";
unique_desc[0x52] = "DEC Pathworks TCPIP service on Windows NT";
unique_desc[0x87] = "Microsoft Exchange MTA";
unique_desc[0x6A] = "Microsoft Exchange IMC";
unique_desc[0xBE] = "Network Monitor Agent";
unique_desc[0xBF] = "Network Monitor Application";

group_desc[0x00] = "Workgroup / Domain name";
group_desc[0x01] = "Master Browser";
group_desc[0x1C] = "Domain Controllers";
group_desc[0x1E] = "Browser Service Elections";
group_desc[0x2F] = "Lotus Notes";
group_desc[0x33] = "Lotus Notes";

function get_nword (blob, pos)
{
 return (ord(blob[pos]) << 8) + ord(blob[pos+1]);
}

function get_ndword (blob, pos)
{
 return (ord(blob[pos]) << 24) + (ord(blob[pos+1]) << 16) + (ord(blob[pos+2]) << 8) + ord(blob[pos+3]);
}

function netbios_encode2(data,service)
{
 local_var tmpdata, ret, i, o, odiv, omod, c;

 ret = "";
 tmpdata = data;

 while (strlen(tmpdata) < 16)
 {
   tmpdata += " ";
 }

 for(i=0;i<16;i++)
 {
   o = ord(tmpdata[i]);
   odiv = o/16;
   odiv = odiv + ord("A");
   omod = o%16;
   omod = omod + ord("A");
   c = raw_string(odiv, omod);

   ret = ret+c;
 }

 return raw_byte (b:strlen(ret)) + ret + raw_byte (b:service);
}

function netbios_decode(name)
{
 local_var tmpdata, ret, i, o, odiv, omod, c;

 ret = NULL;

 for(i=0;i<32;i+=2)
 {
   ret += raw_string ( ((ord(name[i]) - ord("A")) * 16) + (ord(name[i+1]) - ord("A")) );
 }

 return ret;
}

function htons(n)
{
  return raw_string((n >>> 8) & 0xFF, n & 0xFF);
}

function parse_wildcard_response (rep, id)
{
 local_var r_id, flag, questions, answer, authority, additionnal, nbt_length, nbt_encoded, nbt_name;
 local_var pos, service, type, class, ttl, dlen, data, num, names, i;

 r_id = get_nword (blob:rep, pos:0);
 # if it is not our id we leave
 if (r_id != id)
   return NULL;

 flag = get_nword (blob:rep, pos:2);
 # if the error code is != from 0 we leave
 if (flag & 127)
   return NULL;

 questions = get_nword (blob:rep, pos:4);
 if (questions != 0)
   return NULL;

 answer = get_nword (blob:rep, pos:6);
 authority = get_nword (blob:rep, pos:8);
 additionnal = get_nword (blob:rep, pos:10);

 nbt_length = get_byte (blob:rep, pos:12);
 if (strlen (rep) < 12 + nbt_length)
   return NULL;

 nbt_encoded = substr (rep, 13, 13+nbt_length-1);
 nbt_name = netbios_decode (name:nbt_encoded);
 if (nbt_name != wildcard)
   return NULL;

 pos = 13 + nbt_length;
 service = get_byte (blob:rep, pos:pos);
 pos++;

 type = get_nword (blob:rep, pos:pos);
 if (type != 0x21)
   return NULL;

 class = get_nword (blob:rep, pos:pos+2);
 if (class != 1)
   return NULL;

 ttl = get_ndword (blob:rep, pos:pos+4);
 dlen = get_nword (blob:rep, pos:pos+8);
 pos = pos + 10;

 if (strlen(rep) < pos + dlen)
   return NULL;

 data = substr(rep, pos, pos+dlen-1);

 num = get_byte (blob:data, pos:0);
 if (strlen(data) < num*18)
   return NULL;

 pos = 1;
 names = make_list ();

 for (i=0; i < num; i++)
 {
  names[i] = substr(data, pos, pos+17);
  pos += 18;
 }

 # MAC address
 names[i] = substr(data,pos,pos+5);

 return names;
}

function netbios_wildcard_request (socket)
{
 local_var netbios_name, id, name_query_request, buf;

 netbios_name = netbios_encode2 (data:wildcard, service:0x00);

 id = rand() % 65535;

 name_query_request = raw_string (
	htons (n:id)          + # transaction ID
	htons (n:0)           + # Flags (0 == query)
	htons (n:1)           + # qdcount == 1
	htons (n:0)           + # answer
	htons (n:0)           + # authority
	htons (n:0)           + # additional
	netbios_name          + #
        htons (n:0x21)        + # question type = NBSTAT
	htons (n:1)             # question class = IN
	);

 send (socket:socket, data:name_query_request);
 buf = recv (socket:socket, length:4096);

 if (strlen(buf) < 50)
   return NULL;

 return parse_wildcard_response (rep:buf, id:id);
}

function parse_name (name)
{
 local_var tmp, ret;

 tmp = substr (name, 0, 14);
 tmp = ereg_replace(pattern:"([^ ]*) *$", string:tmp, replace:"\1");

 # "\x01\x02__MSBROWSE__\x02"
 if (hexstr(tmp) == "01025f5f4d5342524f5753455f5f02")
   tmp = "__MSBROWSE__";

 ret = make_list();
 ret[0] = tmp;
 ret[1] = ord(name[15]);
 if ( strlen(name) - 16 - 2 >= 0 )
  ret[2] = get_nword (blob:name, pos:16);
 else
  ret[2] = NULL;

 return ret;
}

function get_description (name, number, flags)
{
 local_var desc;

 # Group
 if (flags & 0x8000)
 {
  desc = group_desc[number];
  if (isnull(nbgroup) && !isnull(desc))
  {
   if (((number == 0x00) || (number == 0x1C)) && (!egrep(pattern:"^INet~", string:name)))
     nbgroup = name;
  }
  if (!isnull(desc) && (number == 0x1C) && (egrep(pattern:"^INet~", string:name)))
    desc += " (IIS)";
 }
 # Unique
 else
 {
  if (number == 0x03)
  {
   if (messenger_count != 1)
   {
    desc = unique_desc[number];
    messenger_count++;
   }
   else
   {
    desc = "Messenger Username";
    set_kb_item (name:"SMB/messenger", value:name);
    if("NSNETAPP" >< name)
    set_kb_item(name:"SMB/NetApp", value:TRUE);
   }
  }
  else
  {
   desc = unique_desc[number];
   if (isnull(nbname) && !isnull(desc))
   {
    if (((number == 0x00) || (number == 0x20)) && (!egrep(pattern:"^IS~", string:name)))
      nbname = name;
   }
   if (!isnull(desc) && (number == 0x00) && (egrep(pattern:"^IS~", string:name)))
     desc += " (IIS)";
  }
 }

 if (strlen(desc) <= 0)
   desc = "Unknown usage";

 return desc;
}

## Main code ##

report = NULL;

port = 137;

if ( get_udp_port_state(port))
{
 soc = open_sock_udp (port);
 if (soc)
 {
 rep = netbios_wildcard_request (socket:soc);

 if (!isnull(rep) && max_index(rep) > 1)
 {
  register_service(port:137, proto:"netbios-ns", ipproto:"udp");
  set_kb_item(name:"SMB/NetBIOS/137", value:TRUE);

  report =   string("The following ", max_index(rep)-1, " NetBIOS names have been gathered :\n\n");

  for (i=0; i<max_index(rep)-1; i++)
  {
   name = rep[i];
   val = parse_name (name:name);
   description = get_description (name:val[0], number:val[1], flags:val[2]);

   report += string(" ", val[0], crap(data:" ", length:16 - strlen(val[0]))," = ",description,"\n");
  }

  mac = rep[max_index(rep)-1];

 if(hexstr(mac) == "000000000000")
 {
   set_kb_item(name:"SMB/samba", value:TRUE);
   report += '\n' + 'This SMB server seems to be a Samba server - its MAC address is NULL.';

   replace_kb_item(name:"SMB/not_windows", value:TRUE);
 }
 else
  {
    macstr = strcat(
      hexstr(mac[0]), ":",
      hexstr(mac[1]), ":",
      hexstr(mac[2]), ":",
      hexstr(mac[3]), ":",
      hexstr(mac[4]), ":",
      hexstr(mac[5])
    );

    if (macstr == ":::::")
    {
      replace_kb_item(name:"SMB/not_windows", value:TRUE);
      report += '\n' + 'This SMB server seems not to be Windows - its MAC address is empty.';
    }
    else
    { 
      set_kb_item(name:"SMB/mac_addr", value:macstr);
      report += '\n' + 'The remote host has the following MAC address on its adapter :' +
                 '\n' +
                 '\n' + '   ' + macstr;
    } 
  }

  set_kb_item(name:"/tmp/10150/report", value: report);
  set_kb_item(name:"/tmp/10150/port", value: port);
  set_kb_item(name:"/tmp/10150/proto", value: "udp");
  security_note(port:137, proto:"udp", extra:report);
  }
 }
}

if (isnull(report))
{
 port = 445;

 if(! smb_session_init(smb2:FALSE)) audit(AUDIT_FN_FAIL, 'smb_session_init');
 r = NetUseAdd(share:"IPC$");
 if ( r == 1 )
  NetUseDel();

 list = session_get_addrlist();
 if (!isnull(list))
 {
   list = parse_addrlist(addrlist:list);

   nbname = list[1];
   domain = list[2];

   if (!isnull(nbname) && !isnull(domain))
   {
    report =   string("The following 2 NetBIOS names have been gathered :\n\n");
    sp = 16;
    if (strlen(nbname) >= sp || strlen(domain) >= sp)
    {
      if (strlen(nbname) > strlen(domain)) sp = strlen(nbname);
      else sp = strlen(domain);
    }
    report += string(" ", nbname, crap(data:" ", length:sp - strlen(nbname))," = ",unique_desc[0x00],"\n");
    report += string(" ", domain, crap(data:" ", length:sp - strlen(domain))," = ",group_desc[0x00],"\n");
    set_kb_item(name:"/tmp/10150/report", value: report);
    set_kb_item(name:"/tmp/10150/port", value: port);
    set_kb_item(name:"/tmp/10150/proto", value: "tcp");
    security_note(port:445, proto:"tcp", extra:report);
   }
 }
}

if (!isnull(nbname))
{
 set_kb_item(name:"SMB/name", value:nbname);
 if ( defined_func("report_xml_tag") )
	report_xml_tag(tag:"netbios-name", value:nbname);

 set_kb_item(name:"SMB/netbios_name", value:TRUE);
}
else
{
 set_kb_item(name:"SMB/name", value:get_host_ip());
 set_kb_item(name:"SMB/netbios_name", value:FALSE);
}

if (!isnull(nbgroup))
{
 set_kb_item(name:"SMB/workgroup", value:nbgroup);
}
