#TRUSTED 169d4ac33b35df1d5dbf940e404eee5f3d95cd8be8694f61fe6a2fbe1a3c950ceb1112f57a511e395eb707319aad170b0efdd8f3cf16026fda24ed752b6132809956b5bd6ea7cbadcc9c12efd70de9a9afeb48e6d4555909a55afb4c472199f8be716369e00af3cdba0f36553c805870f229b933bb35a3f6c3dc92572e977f0b1cbf01d3150804f351952c9897d9cd0b0b663c7a838755e1432fc438e12c25a0af75c0ca46e2ed05bee6a7abb53d5e96cb17e8065145dca5915ee2a676f861e88c9024f0695e95be2d7f05175b4fbd3a8a968be561805f2bfb2cd65aa8bcde574066902862ffef00588dae9201b9f49a9c5af374cb20fa8336dae6784fcec9d297f5eface7af5e8c1f06f173c9ddc5812a949285eae24badcde489ce8e56d4c295029f272a33f8ff3a0793363f02f68db2a91dd4ecf781099148e3396b3ed5e1379e2bab7d0eac314a0b86913ad616ca4d2cdcfacc50c80b6f7e7871b4582ad251884bcddf84d631283fb3b8de4c7b754b50f66b38737e32e434e6086901448c6968be2daba43c49c1265b8b448077e3e33d710de2052fc517ec11a0abe84a6e40666649678631a461cb59a9844a60c017f3fb3fd151c8d81c1f55589a6f49e8638a81362fa7ba1ea384d5fa2929a698f5219470ebf0bf100eee089c5c5ef600782536496d5023ccae702e4dd3b471c94f8461fa2c1c5867811be585a7f5d0c1
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("get_local_mac_addr")) exit(0);
if (! defined_func("inject_packet")) exit(0);

include("compat.inc");

if (description)
{
 script_id(53514);
 script_version("1.9");
 script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/29");

 script_cve_id("CVE-2011-0657");
 script_bugtraq_id(47242);
 script_osvdb_id(71780);
 script_xref(name:"IAVA", value:"2011-A-0039");
 script_xref(name:"MSFT", value:"MS11-030");

 script_name(english:"MS11-030: Vulnerability in DNS Resolution Could Allow Remote Code Execution (2509553) (remote check)");
 script_summary(english:"Checks if the DNS resolution supports invalid addresses");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
installed Windows DNS client.");
 script_set_attribute(attribute:"description", value:
"A flaw in the way the installed Windows DNS client processes Link-
local Multicast Name Resolution (LLMNR) queries can be exploited to
execute arbitrary code in the context of the NetworkService account.

Note that Windows XP and 2003 do not support LLMNR and successful
exploitation on those platforms requires local access and the ability
to run a special application. On Windows Vista, 2008, 7, and 2008 R2,
however, the issue can be exploited remotely.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-030");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows DNSAPI.dll LLMNR Buffer Underrun DoS');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/21");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

 script_require_keys("Services/udp/llmnr");

 script_dependencies('llmnr-detect.nasl');
 exit(0);
}

include("global_settings.inc");
include('misc_func.inc');
include('raw.inc');

# Get the port
port = get_service(svc:'llmnr', ipproto:"udp", default:5355, exit_on_fail:TRUE);
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

if (islocalhost()) exit(1, "Can't check against localhost.");
if (!islocalnet()) exit(1, "Host isn't on a local network.");

# Build and send a query
question = 'in-addr.arpa';
split_address = split(get_host_ip(), sep:'.', keep:FALSE);
foreach octet(split_address)
  question = octet + 'a.' + question;

# This is basically a standard DNS PTR query
ptr_query = '\x13\x37' + # Transaction ID
            '\x00\x00' + # Flags - none
            '\x00\x01' + # Questions
            '\x00\x00' + # Answers
            '\x00\x00' + # Authority
            '\x00\x00' + # Additional
            mkbyte(strlen(question)) + question + '\x00' + # Question
            '\x00\x0c' + # Type = PTR
            '\x00\x01';  # Class = IN;

mac_addr = get_local_mac_addr(); # MAC Address of the local host
if(!mac_addr)
  exit(1, "Couldn't get the local MAC address.");
remote   = get_gw_mac_addr(); # MAC Address of the remote host
if(!remote)
  exit(1, "Couldn't get the target MAC address.");

# Open the port to listen to the response
bind_result = bind_sock_udp();
if(isnull(bind_result)) exit(1, "Couldn't create a UDP listener.");
s = bind_result[0];
src_port = bind_result[1];

# Create the packet and put it on the wire
packet = link_layer() + mkpacket(ip(ip_dst:"224.0.0.252", ip_src:this_host(), ip_p:IPPROTO_UDP), udp(uh_dport:5355, uh_sport:src_port), payload(ptr_query));

response = NULL;
for(i = 0; i < 3 && isnull(response); i++)
{
  inject_packet(packet:packet);
  response = recv(socket:s, length:4096, timeout:2);
}

# If the host didn't respond, it probably isn't vulnerable
if(isnull(response) || response == '')
  exit(0, "The host didn't respond - it likely is not affected.");

# Check that the message was successful
if(!(getword(blob:response, pos:2) & 0x8000))
  exit(1, "Didn't receive a valid response from the remote LLMNR server.");

security_hole(port:port, proto:"udp");

