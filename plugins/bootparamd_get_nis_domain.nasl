#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(12237);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/09/24 20:59:28 $");

 script_name(english:"RPC bootparamd NIS Domain Name Disclosure");
 script_summary(english:"Checks the presence of a RPC service");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote RPC service is disclosing information."
 );
 script_set_attribute(attribute:"description", value:
"Using the remote bootparamd service, it was possible to obtain the
NIS domain of the network.  A remote attacker could use this
information to mount further attacks." );
 script_set_attribute(
   attribute:"solution",
   value:"Filter incoming traffic to this port."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/05/13");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"RPC");
 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");
 script_dependencie("rpc_portmap.nasl");
 script_require_keys("rpc/portmap");
 exit(0);
}

include("misc_func.inc");
include("sunrpc_func.inc");


function getpad(f)
{
 f = f % 255;
 if(f < 0x7F)
  return(raw_string(0x00, 0x00, 0x00, f));
 else
  return(raw_string(0xFF, 0xFF, 0xFF, f));
}

function extract_name(data)
{
 local_var clt_len, _i, nam;
 clt_len = ord(data[27]);
 nam = "";
 for(_i = 0; _i < clt_len ; _i = _i + 1)
 {
  nam = string(nam, data[28+_i]);
 }
 return(nam);
}

function extract_domain(data)
{
 local_var align, clt_len, dom, dom_len, _i;
 clt_len = ord(data[27]);
 align = 4 - clt_len%4;
 if(align == 4)align = 0;


 dom_len = ord(data[27+clt_len+align+4]);
 dom = "";
 for(_i=0;_i<dom_len;_i=_i+1)
 {
  dom = string(dom, data[27+clt_len+align+5+_i]);
 }
 return(dom);
}


nis_dom = "";

RPC_PROG = 100026;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
if(!port)exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");


ip = split(get_host_ip(), sep:".", keep:FALSE);
ip_a = int(ip[0]);
ip_b = int(ip[1]);
ip_c = int(ip[2]);
ip_d = int(ip[3]);

pada = getpad(f:ip_a);
padb = getpad(f:ip_b);
padc = getpad(f:ip_c);
res = NULL;
soc = open_sock_udp(port);


for(ip_d = 1; ip_d < 254; ip_d ++ )
{
 padd = getpad(f:ip_d);
 req = raw_string(rand()%256, rand()%256, rand()%256, rand()%256, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xBA, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01) + pada + padb + padc + padd;
 send(socket:soc, data:req);
}

ip_d = int(ip[3]);
r = recv(socket:soc, length:4096);
if ( r )
{
  	name =  extract_name(data:r);
	domain = extract_domain(data:r);
	res = res + string(ip_a, ".", ip_b, ".", ip_c,".", ip_d , " - ", name, " - NIS domain : ", domain, "\n");
}

close(soc);

if(strlen(res))
{
 report = string(
   "\n",
   "Nessus was able to obtain the name of the NIS domain on the network :\n\n",
   "  ", res, "\n"
 );
 security_warning(proto:"udp", port:port, extra:report);
 if( domain )set_kb_item(name:"RPC/NIS/domain", value:domain);
}
