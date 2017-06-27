#TRUSTED 3496e2d52546107dc7e79efe5d299d579b860087b6f1e9e07f8950d2494ee54386aedfe6be9ad1b3ed184968ad668b7a6b082482095c8940f828589e288d1692ab9521eb5db09e270fcf3ae18dd5f97ff9cde317479a079c7008a1827f65577c80dc37c377ecc28572ed3e02cb7880d59066c0e9b034d638ec44eea6ea18335000d9971b5ea315e9b4471384c91332a8c4d2b5e34a5c540c36e38a882b5d6428f0a47275611aedf8b48a4368c702f40a9aca0287966fbb15fb5654cdebcf10bdd0760f0780d1842c2ba345d8ae607c0e1f933153e8296a904fc0bef51c706bf4bdf4894688e135540d35ca0ac1801a3687fa88de5282e4f533c83199662dd9933a648593dd0a22a7e161e5f4846ffdb4504b80236c67f4923d057f4b829e72fa3bcbba8e3bbf1b706f9cb275b2891060d7f1c53b112b736dde5960d3ed778ae1d7029b6b9883decd7bdc4aeaa1d330a7e31d09e81aaa7fa5a362ff3f400f7e81479b3c223f2918abfd3888a6998f318b26781d54df26b01e86211df8ca98f93d46552a22bc22db9bbd691543261e3b825f5533b50e2ceed21f1e02088538c1f2f8e07c9a5a87c0785e2d4051acac4b366b5c27ed0991d6c303acc54105dafe46fdb0d425a005c24432f9e3dd6e2059dbe44ae03e42620cb0f19d608eef9925862e66cc842a9a6d8273232dfb00af1c861b8f42ddc2a0a69e25777f8f906cf382
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(45399);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2011/03/21"); 

 script_name(english:"ICMP Node Information Query Information Disclosure");
 script_summary(english:"Sends an ICMP_NIQ");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host answers to an ICMPv6 Node Information Query and
responds with its DNS name, the list of IPv4 addresses and the list of
IPv6 addresses to which it is bound. 

An attacker can use this information to understand how the network is
architected, which may help him bypass filters.");
 script_set_attribute(attribute:"solution", value:
"Reconfigure the remote host so that it does not answer to these
requests.  Set up filters that deny ICMP packets of type 139." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2010/04/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");
 script_family(english:"General");
 
 exit(0);
}


include('raw.inc');

if ( ! TARGET_IS_IPV6 ) exit(0, "The target is not accessed via IPv6.");

function mk_icmp_niq(csum, nonce, qtype)
{
 local_var icmp;

 icmp = mkbyte(139) + # type
       mkbyte(0)   + # Code
       mkword(csum)   + # Checksum
       mkword(qtype) + # Query Type
       mkword(0x003e) + # Flags
       nonce + 
       get_host_raw_ip();
 return icmp;
}

function csum()
{
 return inet_sum(this_host_raw() +
            get_host_raw_ip() +
           '\0\0' +                     
           mkword(strlen(_FCT_ANON_ARGS[0])) +     
           '\0\0\0' +                   
           mkbyte(58) +    
           _FCT_ANON_ARGS[0]);
}

function icmp_niq()
{
 local_var i, rep;
 local_var pkt;
 local_var nonce, icmp;
 local_var qtype;

 qtype = _FCT_ANON_ARGS[0];
 nonce = mkdword(rand()) + mkdword(rand());
 icmp = mk_icmp_niq(qtype:qtype, csum:0, nonce:nonce);
 icmp = mk_icmp_niq(qtype:qtype, csum:csum(icmp), nonce:nonce);
 pkt = mkpacket(ip6(ip6_nxt:0x3a), payload(icmp));
 for ( i = 0 ; i < 3 ; i ++ )
 {
  rep = inject_packet(packet:link_layer() + pkt, filter:"ip6 and icmp6 and src " + get_host_ip() + " and dst " + this_host(), timeout:2);
  if ( isnull(rep) ) continue;
  if ( strlen(rep) < 40 + strlen(link_layer())) continue;
  if ( ord(rep[40 + strlen(link_layer())]) == 140 ) break;
  rep = NULL;
 }
 if ( rep == NULL ) exit(0); # Not supported
 if ( ord(rep[41 + strlen(link_layer())]) != 0 ) return NULL;
 if ( strlen(rep) <= 56 + strlen(link_layer())) return NULL;
 return substr(rep, 56 + strlen(link_layer()), strlen(rep) - 1 );
}

function ip6_addr()
{
 local_var str;
 local_var i;
 local_var oct;
 local_var ret;

 str = _FCT_ANON_ARGS[0];
 for ( i = 0 ; i < strlen(str) ; i += 4 )
 {
  if ( strlen(ret) > 0 ) ret += ":";
  oct = substr(str, i, i + 3);
  while ( strlen(oct) && oct[0] == "0" ) oct = substr(oct, 1, strlen(oct) - 1);
  if ( oct == "0" ) oct = "";
  ret += oct;
 }
 ret = ereg_replace(pattern:"::+", replace:"::", string:ret);
 return ret;
}

function ip4_addr()
{
 local_var ip;
 ip = _FCT_ANON_ARGS[0];
 return strcat(ord(ip[0]), '.', ord(ip[1]), '.', ord(ip[2]), '.', ord(ip[3]));
}


DNS = 2;
IP6 = 3;
IP4 = 4;

if ( isnull(link_layer()) ) exit(0, "Can not use packet forgery over this interface.");

rep = icmp_niq(DNS);
report = "";
if ( rep != NULL )
{
 pos = 4;
 name = "";
 while ( pos < strlen(rep) )
 {
  if ( pos + 1 >= strlen(rep) ) break;
  len = getbyte(blob:rep, pos:pos);
  pos ++;
  if ( len == 0 ) break;
  if ( strlen(name) ) name += ".";
  if ( pos + len >= strlen(rep) ) break;
  name += substr(rep, pos,  pos + len - 1);
  pos += len;
 }
 if ( strlen(name) ) report += '\n+ The DNS name of the remote host is :\n\n' + name + '\n';
 dns_name = name;
}

rep = icmp_niq(IP6);
if ( rep != NULL )
{
 pos = 0;
 ip6 = "";
 while ( pos < strlen(rep) )
 {
  if ( pos + 4 >= strlen(rep) ) break;
  ttl = getdword(blob:rep, pos:pos);
  pos += 4; 
  if ( pos + 16 > strlen(rep) ) break;
  addr = substr(rep, pos, pos + 15);
  pos += 16; 
  set_kb_item(name:"Host/ICMP/NIQ/IP6Addrs", value:ip6_addr(hexstr(addr)));
  ip6 += ip6_addr(hexstr(addr)) + " (TTL " + ttl + ')\n';
 }
  if ( strlen(ip6) ) report += '\n+ The remote host is bound to the following IPv6 addresses :\n\n' + ip6 + '\n';
}
rep = icmp_niq(IP4);
if ( rep != NULL )
{
 pos = 0;
 ip4 = "";
 if ( strlen(dns_name) && dns_name >!< rep ) # Mac OS X bug
 {
 while ( pos <= strlen(rep) ) 
  {
   if ( pos + 4 >= strlen(rep) ) break;
   ttl = getdword(blob:rep, pos:pos);
   pos += 4;
   if ( pos + 4 > strlen(rep) ) break;
   set_kb_item(name:"Host/ICMP/NIQ/IP4Addrs", value:ip4_addr(substr(rep, pos, pos + 3)));
   ip4 += ip4_addr(substr(rep, pos, pos + 3)) + ' (TTL ' + ttl + ')\n';
   pos += 4;
  }
  if ( strlen(ip4) ) report += '\n+ The remote host is bound to the following IPv4 addresses :\n\n' + ip4 + '\n';
 }
}

if ( strlen(report) ) security_note(port:0, proto:'icmp', extra:report);
