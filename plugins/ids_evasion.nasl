#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

# The HTTP IDS evasion mode comes from Whisker, by RFP.
# It has been moved to http_ids_evasion.nasl
#
# The TCP IDS evasion techniques are largely inspired by
# the work from Tom Ptacek and Tim Newsham.

if ( NASL_LEVEL >= 3000 ) exit(0);


include("compat.inc");

if(description)
{
 script_id(10889);
 script_version ("$Revision: 1.30 $");
 script_cvs_date("$Date: 2015/08/03 18:01:48 $");

 script_name(english:"NIDS Evasion Options");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin configures Nessus for NIDS evasion." );
 script_set_attribute(attribute:"description", value:
"This plugin configures Nessus for NIDS evasion (see the 'Prefs' panel).
NIDS evasion options are useful if you want to determine
the quality of the expensive NIDS you just bought.

TCP Evasion techniques :
- Split : send data one byte at a time. This confuses
  NIDS which do not perform stream reassembly
  
- Injection : same as split, but malformed TCP packets
  containing bogus data are sent between normal packets. 
  Here, a 'malformed' tcp packet means a legitimate TCP packet 
  with a bogus checksum.
  This confuses NIDS which perform stream reassembly but do
  not accurately verify the checksum of the packets or
  do not determine if the remote host actually
  receives the packets seen ;
  
- Short TTL : same as split, but a valid TCP packets
  containing bogus data are sent between normal packets.
  These packets have a short (N-1), meaning that if
  the NIDS is on a gateway, it will see these packets
  go through, but they will not reach the target
  host.
  This confuses NIDS which perform stream reassembly
  but do not accurately check if the packet can actually
  reach the remote host or which do not determine if the 
  remote host actually receives the packets seen ;

- Fake RST : each time a connection is established, Nessus
  will send a RST packet with a bogus tcp checksum or
  a bogus ttl (depending on the options you chose above),
  thus making the IDS believe the connection was closed
  abruptly.
  This confuses badly written NIDS which believe
  anything they see.
  
Warning: those features are experimental and some 
options may result in false negatives!
This plugin does not do any security check." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/02/19");
 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_summary(english:"NIDS evasion options");
 script_category(ACT_SETTINGS);
 script_copyright(english:"This script is Copyright (C) 2002-2015 Tenable Network Security, Inc.");
 script_family(english:"Settings");
 
 script_add_preference(name:"TCP evasion technique", type:"radio", value:"none;split;injection;short ttl");

 script_add_preference(name:"Send fake RST when establishing a TCP connection",
 	type:"checkbox", value:"no");
 exit(0);
}

pref =  script_get_preference("TCP evasion technique");
if(!pref)exit(0);

if(pref == "none")exit(0);


if(pref == "none;split;injection;short ttl")exit(0);

if(pref == "split")
{
 set_kb_item(name:"NIDS/TCP/split", value:"yes");

  if (! get_kb_item("Settings/Whisker/NIDS"))
    set_kb_item(name: "Settings/Whisker/NIDS", value: "9");

w="TCP split NIDS evasion function is enabled. Some tests might
run slowly and you may get some false negative results";
 security_note(port:0, protocol:"tcp", data:w);
}

if(pref == "injection")
{
 set_kb_item(name:"NIDS/TCP/inject", value:"yes");
w="TCP inject NIDS evasion function is enabled. Some tests might
run slowly and you may get some false negative results.";
 security_note(port:0, protocol:"tcp", data:w);
}


if(pref == "short ttl")
 {
 set_kb_item(name:"NIDS/TCP/short_ttl", value:"yes");
w="TCP short ttl NIDS evasion function is enabled. Some tests might
run slowly and you may get some false negative results.";
 security_note(port:0, protocol:"tcp", data:w);
 }


pref = script_get_preference("Send fake RST when establishing a TCP connection");
if(!pref) exit(0);

if(pref == "no")exit(0);



if(pref == "yes") {
 set_kb_item(name:"NIDS/TCP/fake_rst", value:"yes");
w="TCP fake RST NIDS evasion function is enabled. Some tests might
run slowly and you may get some false negative results.";
 security_note(port:0, protocol:"tcp", data:w);
}

