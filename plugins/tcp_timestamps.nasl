#TRUSTED 18c379c8fbaafcff9c399d207da5629072fd0ceeaf720991bf3e2428337bfd927aa03d9a3200a919ff710d587ecbe70acc57aa48742aa76419bb78c6f668fc46ebfc9be1fbd1c8e113ed849721f5b72630a950f8c56a7ecc5d9842c9bddf396931192a156abeadd579ae9ef7488ccaaed116ea1709a7a1fadbe6c227b1caffd4b1e024f075914e7c3f405ded696a9eabea07add803c054c7ce988a226369dbb96e710ae3f5cc7bd08e1f38b5321d2da98bb00534ff8e40338e724b6e1772b0afc2f796d7af9d8cb121b0d51ab600b479df8844bf467fccd4d3c341c4b006a352d482127544443a057b0bf3133bb997679c59f7da5ac7dac98589f84ee4ee619efdfaa34a723869aabe23e916c8e87133b731e00b7360343e036b6f325883cb7663604d779ebec1e805872c7cc1ea8e071474dd006c48323e7760cb42c0d761236b7c05c5f3ac5ca340d14759473f7360f568a5b2d7108be763f9823bb7cb239c599dafaf05c7b4de7ff8aa411ad96f1a46d6a35910b7d407aabdcff68c729a4844a560a595c4c00848d84178650b5cf460e320e28972c21a86a027f4713cfe131f590c37867d4161ae23925ccba46be359924a217ddf54a18f0fbde2bea937a82c872353308f8d49c4b81f29eade2315272fce20b8f15103edbc77fb3901047e19ae2d15dfae6f097880c0a3aafb9d67203a5514465834b1ceaded06a2e0013d
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25220);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2011/03/20");

  script_name(english: "TCP/IP Timestamps Supported");
  script_summary(english: "Look at RFC1323 TCP timestamps"); 
 script_set_attribute(attribute:"synopsis", value:
"The remote service implements TCP timestamps." );
  script_set_attribute(attribute:"description", value:
"The remote host implements TCP timestamps, as defined by RFC1323.  A
side effect of this feature is that the uptime of the remote host can
sometimes be computed." );
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc1323.txt" );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "General");
  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

  exit(0);
}


include("raw.inc");

function ms_since_midnight()
{
  local_var     v, s, u;

  if (defined_func("gettimeofday"))
  {
    v = split(gettimeofday(), sep: '.', keep: 0);
    s = int(v[0]); u = int(v[1]);
    s %= 86400;
    u /= 1000;
    return u + 1000 * s;
  }

  if (defined_func("unixtime"))
  {
    s = unixtime();
    s %= 86400;
    return s * 1000;
  }

  return NULL;
}




if ( TARGET_IS_IPV6 ) exit(0, "This plugin is for IPv4 only.");
if ( islocalhost() ) exit(0, "The target is the localhost.");

dport = get_host_open_port(); 
if (! dport) exit(0, "No open port.");

daddr = get_host_ip();
saddr = this_host();


function test(seq)
{
 local_var ip, tcp, options, filter, ms, r, sport, tsval;
 local_var i;
 local_var pkt;

 sport = rand() % (65536 - 1024) + 1024;
 ip = ip(ip_p:IPPROTO_TCP);
 tcp = tcp(th_sport:sport, th_dport:dport, th_flags:TH_SYN, th_win:512);
 tcp = tcp_insert_option(tcp:tcp, type:0x08, length:0x0A, data:mkdword(seq) + mkdword(0) + '\0x01\0x01');
 tcp = tcp_finish_insert_option(tcp:tcp);

 filter = strcat('tcp and src ', daddr, ' and dst ', saddr, ' and src port ', dport, ' and dst port ', sport);
 if ( ! defined_func("link_layer") )  RawSendViaOperatingSystem = 1;
 pkt = mkpacket(ip, tcp);
 for ( i = 0 ; i < 5 ; i ++ )
 {
  if ( ! defined_func("link_layer") )
  {
    r = send_packet(pkt,  pcap_active: TRUE, pcap_filter: filter, pcap_timeout:1);
    if ( !isnull(r) ) break;
  }
  else 
  {
   r = inject_packet(packet:link_layer() + pkt,filter:filter, timeout:1);
   if ( !isnull(r) ) 
	{
	 r = substr(r, strlen(link_layer()), strlen(r) - 1);
	 break; 
	}
   }
  }
 if ( r == NULL ) return NULL;
 ms = ms_since_midnight();

 pkt = packet_split(r);
 if ( isnull(pkt) ) return NULL;
 pkt = pkt[1];
 if ( isnull(pkt) || pkt["type"] != "tcp" ) return NULL;
 pkt = pkt["data"];
 if ( ! ( pkt["th_flags"] & TH_ACK) ) return NULL;
 if ( isnull(pkt["options"]) ) return NULL;
 tsval = tcp_extract_timestamp(pkt["options"]);
 if (isnull(tsval)) return NULL;
 return make_list(ms, tsval);
}

function tcp_extract_timestamp()
{
 local_var opt, lo, n, i, tsval, tsecr, len;
 
 opt = _FCT_ANON_ARGS[0];
 lo = strlen(opt);
 for (i = 0; i < lo; )
 {
  n = ord(opt[i]);
  if (n == 8)	# Timestamp
  {
   tsval = getdword(blob: substr(opt, i+2, i+5), pos:0);
   tsecr = getdword(blob: substr(opt, i+6, i+9), pos:0);
   #debug_print(level: 2, "TSVal=", tsval, " TSecr=", tsecr, "\n");
   return tsval;
  }
  else if (n == 1)	# NOP
   i ++;
  else
  {
   if ( i + 1 < strlen(opt) )
    len = ord(opt[i+1]);
   else 
    len = 0;
   if ( len == 0 ) break;
   i += len;
  }
 }
 return NULL;
}

function sec2ascii(txt, s)
{
 if (s < 60) return '';
 if (s < 3600)
  return strcat(txt, (s + 29) / 60, ' min');
 else if (s < 86400)
  return strcat(txt, (s + 1799) / 3600, ' hours');
 else
  return strcat(txt, (s + 23199) / 86400, ' days');
}

####

v1 = test(seq:1);

if (isnull(v1)) exit(0, "No valid TCP answer was received.");

# A linear regression would not be more precise and NASL is definitely not
# designed for computation! We would need floating point.
sleep(1);	# Bigger sleep values make the test more precise

v2 = test(seq: 2);
if (isnull(v2)) exit(1, "Invalid or no TCP answer."); # ???
else
{
 dms = v2[0] - v1[0];
 dseq = v2[1] - v1[1];

 #
 # Disable the uptime computation (unreliable)
 #
 if ( TRUE || dseq == 0 || v2[1] < 0)
 {
  security_note();
 }
 else
 {
  hz = dseq * 1000 / dms; hz0 = hz;
  # Round clock speed
  if (hz > 500) { hz = (hz + 25) / 50; hz *= 50; }
  else if (hz > 200) { hz = (hz + 5) / 10; hz *= 10; }
  else if (hz > 50) { hz = (hz + 2) / 5; hz *= 5; }
  #debug_print('dms = ', dms, ' - dseq = ', dseq, ' - clockspeed = ', hz0, ' rounded = ', hz, '\n');
  uptime = v2[1] / hz;
  #uptime = v2[1] * (dms / dseq) / 1000;
  txt = '';
  txt = sec2ascii(txt: ', i.e. about ', s: uptime);
  ov = (1 << 30) / hz; ov <<= 2;
  txt = strcat(txt, '.\n\n(Note that the clock is running at about ', 
	hz, ' Hz', 
	' and will\noverflow in about ', ov, 's', 
	sec2ascii(txt: ', that is ', s: ov));
  security_note(port: 0, 
	extra:strcat('The uptime was estimated to ', 
		uptime, 's', 
		txt, ')') );
 }
}
