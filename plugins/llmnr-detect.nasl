#TRUSTED 823c0baaddd486c906098e30e4f886242bf386940d4efe91692d3cae7b1725b9cef256b75c79c1e9816154da0c7a6d2dbc232860b8012695921484de295c259593ff6f473bf85deb9f0bc1811f3a05adbae97c4df2e6fb235b071b69d70487d71624a7668147ee777d6498534b90c8b6df2823d34e54ec6164b6b005da2ab522deab066f7f74e274c296d09bae6042ddc4489aede4d665fd97b9974899e3e9b68ee29c29df7488f883b5f77c30d8a067835bf0585bfa75b3f3f9775118ee5ff76d511b666b621a0b0ff7ea5204ab2fc05b7bc839793536f1e47328216a849d62afe7b9613f58a92ca6ad26b25bca49ce5ea05818ec24d298816e035b397d4a0af5ac28e0e2ab89bbe47fe059bb45564ae854eb351521e3c3dd5b00a2d19eddeafccf663b76c9f94f1d5c8533f1265c8979c0a881dc803e854e0d6e6f92ef6be2e2ad6b03ceffe896d2c96d200c3e14b1823b75772bfa6acc2b632ca94930cb4a2865694b7f3a05d96abd7937df5b097c76af2ec2ec5eb466ccef07c4d689fbd77348b6eb35af4658297e639be35a554623735411d18e41785888abe78b2488a20f43f4348d8837cae6518e8adfe9a33a5186f5cb40f34079c11e4739fa93bb00aae04d14095c7a683bc0fc3f4359874dc354bfdf5cbf20b6b14aeb5ac7ac54ed890b3e5190d3098c3dd6cfd5c8b29fe24bd1b8f432bd3ee2f8266e1aa6a6d75d
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("get_local_mac_addr")) exit(0);
if (! defined_func("inject_packet")) exit(0);

include("compat.inc");

if (description)
{
 script_id(53513);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2012/03/05");

 script_name(english: "Link-Local Multicast Name Resolution (LLMNR) Detection");
 script_summary(english: "Sends a LLMNR PTR request");

 script_set_attribute(attribute:"synopsis", value:"The remote device supports LLMNR.");

 script_set_attribute(attribute:"description", value:
"The remote device answered to a Link-local Multicast Name Resolution
(LLMNR) request.  This protocol provides a name lookup service similar
to NetBIOS or DNS.  It is enabled by default on modern Windows
versions.");

 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?85beb421");
 script_set_attribute(attribute:"see_also", value: "http://technet.microsoft.com/en-us/library/bb878128.aspx");

 script_set_attribute(attribute:"solution", value:
"Make sure that use of this software conforms to your organization's
acceptable use and security policies." );

 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/21");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011-2012 Tenable Network Security, Inc.");
 script_family(english: "Service detection");
 exit(0);
}

include("global_settings.inc");
include('misc_func.inc');
include('dns_func.inc');
include('raw.inc');

# The spec says that the port has to be 5355
port = 5355;
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

if (islocalhost()) exit(1, "Can't check against localhost.");
if (!islocalnet()) exit(1, "Host isn't on a local network.");

# Build and send a query
question = 'in-addr.arpa';
split_address = split(get_host_ip(), sep:'.', keep:FALSE);
foreach octet(split_address)
  question = octet + '.' + question;

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
  exit(1, "Couldn't get local MAC address.");
remote   = get_gw_mac_addr(); # MAC Address of the remote host
if(!remote)
  exit(1, "Couldn't get target MAC address.");

# Open the port to listen to the response
bind_result = bind_sock_udp();
if(isnull(bind_result)) exit(1, "Couldn't create UDP listener.");
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

# If the host doesn't answer, it probably isn't running a LLMNR server
if(isnull(response) || response == '')
  exit(0, "The host didn't respond - either it isn't running LLMNR or it has a restrictive configuration.");

# Register the service
register_service(port:port, ipproto:"udp", proto:"llmnr");

# Just for fun, tell them what the hostname is.
response = dns_split(response);

# Get the name and remove the leading size + trailing null
name = response['an_rr_data_0_data'];
name = substr(name, 1, strlen(name) - 2);

gs_opt = get_kb_item("global_settings/report_verbosity");
if (gs_opt && gs_opt != 'Quiet' && strlen(name) > 0)
{
  report = '\nAccording to LLMNR, the name of the remote host is \'' + name + '\'.\n';
  security_note(port:port, proto:"udp", extra:report);
}
else security_note(port:port, proto:"udp");
