#
# (C) Tenable Network Security, Inc.
#

# Changes by Tenable:
# - Plugin entirely rewritten (2010/05/28)
#

include("compat.inc");

if(description)
{
 script_id(15753);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2015/03/02 16:23:07 $");

 script_cve_id("CVE-2004-0789");
 script_bugtraq_id(11642);
 script_osvdb_id(11575);

 script_name(english:"Multiple Vendor DNS Response Flooding Denial Of Service");
 script_summary(english:"Send a DNS answer to a DNS server");

 script_set_attribute(attribute:"synopsis", value:
"The remote DNS server is vulnerable to a denial of service attack.");
 script_set_attribute(attribute:"description", value:
"The remote DNS server is vulnerable to a denial of service attack
because it replies to DNS responses. 

An attacker could exploit this vulnerability by spoofing a DNS packet so
that it appears to come from 127.0.0.1 and make the remote DNS server 
enter into an infinite loop, therefore denying service to legitimate 
users.");

 script_set_attribute(attribute:"see_also", value:
"http://www.nessus.org/u?a04dcb96");
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for an appropriate upgrade.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/09");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK);
 script_family(english: "DNS");
 script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
 script_require_keys("DNS/udp/53");
 script_dependencies("dns_server.nasl");
 exit(0);
}

#
# The script code starts here
#

include("dns_func.inc");
include("dump.inc");

if ( islocalhost() ) exit(0, "The target is localhost.");
if (! get_kb_item("DNS/udp/53") || ! get_udp_port_state(53) )
 exit(0, "UDP port 53 is closed." );


# Request www.google.com
req["transaction_id"] = rand() % 65535;
req["flags"] = 0x0100;
req["q"]     = 1;
packet = mkdns(dns:req, query:mk_query(txt:dns_str_to_query_txt("www.google.com."), type:0x0010, class:0x0001));

soc = open_sock_udp (53); 
if (!soc) exit(1, "Could not open a socket to UDP:53");

send(socket:soc, data:packet);
r = recv(socket:soc, length:4096);
if ( isnull(r) )
{
  close(soc);
  exit(1, "The remote DNS server did not reply");
}
if (  ( ord(r[2]) & 0x80 ) == 0 )
{
  close(soc);
  exit(1, "Unexpected DNS answer.");
}


# New socket
close(soc);
soc = open_sock_udp (53); 
if (!soc) exit(1, "Could not re-open a socket to UDP:53");

# Send the reply again
orig_response = r;
send(socket:soc, data:r);
r = recv(socket:soc, length:4096);
close(soc);
if ( r && ( ord(r[2]) & 0x80 ) )
{
  report =
    '\nNessus sent the following response data :\n\n' +
    hexdump(ddata:orig_response) +  # hexdump() already has a trailing newline
    '\nAnd the DNS server replied with the following response :\n\n' +
    hexdump(ddata:r); # hexdump() already has a trailing newline
  security_warning(port:53, proto:"udp", extra:report);
}
else exit(0, "The remote DNS server is not vulnerable");
