#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if (description)
{
	script_id(12238);
	script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/11/23 20:31:34 $");
	script_osvdb_id(57734);


	script_name(english:"NIS passwd.byname Map Disclosure");
	script_summary(english:"checks the presence of a RPC service");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to information disclosure'
  );

  script_set_attribute(
    attribute:'description',
    value:"This script fetches the remote NIS 'passwd.byname' map, provided that
the NIS domain name could be obtained."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Disable NIS if it is not required."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(
    attribute:'see_also',
    value:'http://securitydigest.org/zardoz/archive/211'
  );


 script_set_attribute(attribute:"plugin_publication_date", value:"2004/05/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_family(english:"RPC");
	script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
	script_dependencie("bootparamd_get_nis_domain.nasl");
	script_require_keys("RPC/NIS/domain");
	exit(0);
}


include("misc_func.inc");
include("sunrpc_func.inc");

global_var i, len, tcp;

function pad(len)
{
 local_var _i, pad, ret;

 ret= "";
 for(_i = 0; _i < len ; _i = _i + 1)
 {
  ret = string(ret, raw_string(0));
 }
 return(ret);
}

function extract_key(data, tot)
{
 local_var len, len_hi, len_lo, s;

 s = "";
 len_hi = ord(data[34+tcp+tot]);
 len_lo = ord(data[35+tcp+tot]);
 len = len_hi * 256;
 len = len + len_lo;
 s = "";
 for(i=0;i<len;i=i+1)
 {
  s = string(s, data[36+tcp+i+tot]);
 }
 return(s);
}

function extract_data(data)
{
 local_var align, end, entry, f, flag, str, tot;

 str = "";
 end =  strlen(data);
 tot = 0;
 flag = 1;
 f = 3;
 for(;flag;)
 {
  entry = extract_key(data:data, tot:tot);
  align = 4 - len % 4;
  if(align == 4)align = 0;
  tot = tot + i + align + 4;
  if((tot + 40) > strlen(data))flag = 0;
  if(f > 2)
  {
   if(strlen(entry))  str = string(str, entry, "\n");
  f = 1;
  }
  else f = f + 1;
 }
 return(str);
}

nis_dom = get_kb_item("RPC/NIS/domain");
if(!nis_dom)exit(0);

soc = 0;

RPC_PROG = 100004;
port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_TCP);
if (port && get_tcp_port_state(port)) {
	tcp = 4;
	soc = open_priv_sock_tcp(dport:port);
	}

if(!soc)
{
 port = get_rpc_port2(program:RPC_PROG, protocol:IPPROTO_UDP);
 if ( ! port || ! get_udp_port_state(port)) exit(0);
 tcp = 0;
 soc = open_priv_sock_udp(dport:port);
}

if(!soc)exit(0);


len = strlen(nis_dom);
x = len % 256;
y = len / 256;

align = 4 - len%4;
if(align == 4)align = 0;
pad = pad(len:align);
map = "passwd.byname";
len = strlen(map);
x2  = len % 256;
y2  = len / 256;
align = 4 - len%4;
if(align == 4)align = 0;
pad2 = pad(len:align);

req = raw_string(0xDE, 0xAD,
	0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x01, 0x86, 0xA4, 0x00, 0x00,
	0x00, 0x02, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	y, x) + nis_dom + pad + raw_string(0x00, 0x00, y2, x2) +
	map + pad2;

tot_len = strlen(req);
tot_len_hi = tot_len / 256;
tot_len_lo = tot_len % 256;

if(tcp)req = raw_string(0x80, 0x00, tot_len_hi, tot_len_lo) + req;
send(socket:soc, data:req);
if ( tcp ) {
	 data = recv(socket:soc, length:4);
	 if ( ! data ) exit(0);
	 len = ord(data[2]) * 256 + ord(data[3]);
	}
else {
	data = NULL;
	len = 65535;
	}

data += recv(socket:soc, length:len);
if ( ! data ) exit(0);
mapcontent = extract_data(data:data);


if(strlen(mapcontent))
{
 report = string("It was possible to extract the map ", map, " using the NIS domain name ",
nis_dom, " :\n", mapcontent);

 if(tcp)security_warning(port:port, extra:report);
 else security_warning(proto:"udp", port:port, extra:report);
}
