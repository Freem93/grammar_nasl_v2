#TRUSTED 8eb315e6ba751549a04fee7f30a2849ce709207de41181c715b8f36a563282e1ad9807d41d1ec2ec257ea1024944bcf67e8c0db4a7305c9a456a4aed84355364497100c1f697f77ece8414869d83526eb6c327c1be652f05d77182bdbb1e3da32e8e8942f71847211343c09cd60387c1019e56551b6814a7a388ff7a6ecb9ccab1f4f65e00ec1a9c03ed24816d87216bd91cf5d9ddd59d6601a62608c3f5848ab153fc46f08d74a6bc6b13e66beb0b36f004e64fccca7314e0c0a684e03531594bbae3357e9d4b6eda84eda9e35b132350f219efad115dc9695e691e8288bcb77184e3319956a14e66c4653193b1d39c05deb105a120323b656a3ab654dbc2939d9e9afe9a9f6c0e61af4f5d33820570bf9c84fa77c406c34d63e3c441e2fe15ef0a7543747a3690683f7389cde860ae032837f71a88d91cee3afa7b66994cc78a07e03eac39de09fbe1aad78e7da5ab73e5077d71e3f9815381ce8abb9ecd57d37a346e37a97e44cee88ba7265fe726d5ff535fa5b1b4249666204400dccc7d196c36a2d69a51c79090e02fe3a3120f4e3c679b64fcd6b2f71acf1ce27497d294112edc8550232aaccc693e435e5854902f012490d12cbeaa783c39d945bc7cd1db89084ef487a3008a696cc7263c50be833b03c6108077a2e251b7e777a75915e334acb51bf0c61be1a07af869e9205a5d6172bf0df8253844c039a4f3b85f
#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 4200 ) exit(0);
include("compat.inc");

if(description)
{
 script_id(52616);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value: "2012/01/31");

 script_name(english:"Wake-on-LAN");
 script_summary(english:"Wakes up the remote systems");

 script_set_attribute(attribute:"synopsis", value:
"This script wakes the remote computers on the local LAN." );
 script_set_attribute(attribute:"description", value:
"This script will send a WoL (Wake-On-LAN) packet to each MAC address
listed in file uploaded via its preference. 

To use this feature :

  - The scanner must be located on the same physical subnet 
    as the targets.

  - The MAC addresses of the targets must be listed in a 
    text file supplied via the policy (Edit the policy -> 
    Advanced -> Wake-On-LAN). Each MAC address should be 
    supplied on a different line.

This script will cause Nessus to wait 5 minutes (or any value
configured) before starting the scan to give time to the remote
systems to wake up from sleep." );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Wake-on-LAN" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_family(english:"Settings");
 script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
 script_category(ACT_INIT);

 script_add_preference(name:"List of MAC addresses for Wake-on-LAN: ", type:"file", value:"");
 script_add_preference(name:"Time to wait (in minutes) for the systems to boot: ", type:"entry", value:"5");
 script_timeout(0);

 exit(0);
}

include("misc_func.inc");
include("raw.inc");

global_var broadcast, macaddr;

function wol()
{
 local_var line, str, magic, ethernet, payload, wol;

 line = chomp(str_replace(string:_FCT_ANON_ARGS[0], find:":", replace:""));
 if ( (strlen(line) % 2) != 0 )  return 0;
 str = hex2raw(s:line);
 if ( strlen(str) != 6 ) return 0;
 magic = crap(length:6, data:'\xff');
 magic += crap(length:17 * strlen(str), data:str);


 ethernet = broadcast + macaddr + mkword(0x0800);
 payload = mkpacket(ip(ip_p:IPPROTO_UDP), udp(uh_dport:9), payload(magic));

 wol = ethernet + payload;

 inject_packet(packet:wol);
 return 1;
}



if ( islocalhost() ) exit(0);
if ( !islocalnet() ) exit(0);

macs = script_get_preference_file_content("List of MAC addresses for Wake-on-LAN: ");
if ( isnull(macs) || strlen(macs) == 0 ) exit(0);

# Take into account the fact we may be connected to multiple NICs
iface = routethrough();
if ( isnull(iface) ) exit(0, "Could not determine which iface to use.");

mutex_name = "WoL/" + iface;


broadcast = crap(data:raw_string(0xff), length:6);
macaddr   = get_local_mac_addr();

to   = script_get_preference("Time to wait (in minutes) for the systems to boot: ");
if ( int(to) <= 0 ) to = 5;
else to = int(to);

mutex_lock(mutex_name);
if ( get_global_kb_item(mutex_name) )
{
 # The script already ran
 mutex_unlock(mutex_name);
 exit(0);
}

lines = split(macs);
count = 0;
foreach line ( lines )
{
 if ( wol(line) != 0 )
 { 
  count ++;
  usleep(20000);
 }
}

set_global_kb_item(name:mutex_name, value:TRUE);
if ( count > 0 ) 
 {
  # Let the remote systems boot up
  #
  # In order to prevent the systems that were in "sleep" mode to go back to sleep
  # while we wait for others to do a cold boot, we send a new WoL packet every 
  # minute
  #
  deadline = unixtime() + to * 60;
  for ( i = 0 ; i < to ; i ++ )
  {
   if ( unixtime() > deadline ) break;
   foreach line ( lines )
   {
    if ( wol(line) != 0 ) usleep(20000);
   }
   n = 60 - ((count * 20000) / 1000000);
   if ( n > 0 ) sleep(n);
  }
 }
mutex_unlock(mutex_name);
