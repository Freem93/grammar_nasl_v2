#TRUSTED 6b278064c31015ce41894d99bd122283eb7ffcf2d07f9d5226c723004e31632b40197ba54841b8b189f6026b171a1fb78e537560f59e03e26ff73f6a6e74ac65bcee8dbc0c7a53c4d0e908c38cae2fd0a900f967a23963aec60da6aa1454183d95f6b912e13d5c3bf37a210e0a3e98f3c3b0a86206e9f7513b5ce678347317004c079611c0ad5ac46e23342a4a902aa6ef5b633960a4e745097a220f6f0be41299d29a204fc5ee8886edf230a74faf9baf5702fa75142256f21fa7d6541ccebb6f74beb02ab4b2c65c14a2f51391ad65e01542cb78abf6965daba42e5ea99e6c1aefb3fe912335ec1fcfc07ef79caa683fa634a75347e54d8bd9f1725a3d416de333cd476e12dc59e591f778233dd23661ee4cd672f0122a8a224906e79aca2da997ae11296466e9cc68dbc3365360f7bff37a23b8a42b4de766e4f01e301498af1c8d2a60687a049416d8b2890c2a9c67659fc1fb07e27949758428addaa3ebd9b9c63ecbb8a658660197df904e8e3f471a61b5ff20300871fcb517fcdb5fecad84726646415229c459327edfa847e188ccf14c022e256c983386b2e812ebb80c0c53e26ea2a8506cfbed0536b5428fe956124fe30a4dc6ad09463553345f9bcd7639843c553ec961fe2dc93d09fca3533440120ed3d1708f42f02d9cc13147b4b3c63f8820cfec90a5fa18f6c253d1b45b4f212002d9d6c22bec372b9a7449
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(73124);
 script_version("1.3");
 script_set_attribute(attribute:"plugin_modification_date", value:"2016/10/07");

 script_xref(name:"CERT", value:"184540");

 script_name(english:"NAT-PMP Detection (remote network)");
 script_summary(english:"NAT-PMP detection.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to obtain information about the remote network.");
 script_set_attribute(attribute:"description", value:
"The remote device has the NAT-PMP protocol enabled. This protocol
may allow any application on an internal subnet to request port
mappings from the outside to the inside.

If this service is reachable from the outside your network, it may
allow a remote attacker to gain more information about your network
and possibly to break into it by creating dynamic port mappings.");
 script_set_attribute(attribute:"solution", value:
"Filter incoming traffic to UDP port 5351.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");

 script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

 exit(0);
}


include("audit.inc");
include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


function readable_ip()
{
 local_var r;

 r = _FCT_ANON_ARGS[0];
 return strcat(getbyte(blob:r, pos:0), ".",
	       getbyte(blob:r, pos:1), ".",
	       getbyte(blob:r, pos:2), ".",
	       getbyte(blob:r, pos:3));
}


port = 5351;
if (!service_is_unknown(port:port, ipproto:"udp")) exit(0, "The service listening on UDP port " + port + " has already been identified.");

if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");

pkt = mkbyte(0) +  # Protocol version
      mkbyte(0);   # Request public IP address

send(socket:soc, data:pkt);
r = recv(socket:soc, length:1024);
close(soc);

if ( isnull(r) ) exit(0, "NAT-PMP not listening on the remote host.");
if ( strlen(r) < 4 ) exit(1, "NAT-PMP sent an unexpected answer.");
if ( getword(blob:r, pos:2) != 0 ) exit(1, "NAT-PMP rejected our query.");
if ( strlen(r) < 12 ) exit(1, "NAT-PMP sent an unexpected answer.");

public_ip = readable_ip(substr(r, 8, 11));
set_kb_item(name:"Services/udp/nat-pmp", value:port);
set_kb_item(name:strcat("nat-pmp/", port, "/public-ip"), value:public_ip);
if ( !islocalnet() )
{
 report += 'According to the remote NAT-PMP service, the public IP address of this host is :\n\n' + public_ip;

 listen =  bind_sock_tcp();
 soc = open_sock_udp(port);
 pkt = mkbyte(0) + # Protocol version = 0
       mkbyte(2) + # Map TCP
       mkword(0) + # Reserved
       mkword(listen[1]) + # Internal port
       mkword(listen[1]) + # Suggested external port
       mkdword(60);     # Lifetime

 send(socket:soc, data:pkt);
 r = recv(socket:soc, length:1024);
 close(soc);
 if ( strlen(r) >= 12 )
 {
 result = getword(blob:r, pos:2);
 internal_port = getword(blob:r, pos:8);
 mapped_port = getword(blob:r, pos:10);
 if ( result == 0 ) # Success
 {
  pkt = mkbyte(0) + # Protocol version = 0
      mkbyte(2) + # Map TCP
      mkword(0) + # Reserved
      mkword(internal_port) + # Internal port
      mkword(mapped_port) + # Suggested external port
      mkdword(0);     # Lifetime

 soc = open_sock_udp(port);
 send(socket:soc, data:pkt);
 r = recv(socket:soc, length:1024);
 close(soc);
 report += '\nIt was possible to create (and destroy) a mapping from ' + public_ip + ':' + mapped_port + ' to ' + this_host() + ':' + internal_port;
 }
 else report += '\nIt was not possible to create a mapping.';
 }

 security_hole(port:port, proto:'udp', extra:report);
}
