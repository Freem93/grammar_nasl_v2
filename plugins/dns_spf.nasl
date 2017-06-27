#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(31658);
 script_version ("$Revision: 1.10 $");
 script_cvs_date("$Date: 2011/05/24 20:37:07 $");

 script_name(english:"DNS Sender Policy Framework (SPF) Enabled");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote domain publishes SPF records." );
 script_set_attribute(attribute:"description", value:
"The remote domain publishes SPF records.  SPF (Sender Policy
Framework) is a mechanism to let an organization specify their mail
sending policy, such as which mail servers are authorized to send mail
on its behalf." );
 script_set_attribute(attribute:"see_also", value:"http://www.openspf.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/26");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_summary(english: "Performs a TXT query against the remote domain");
 script_category(ACT_GATHER_INFO); 
 
 script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
 script_family(english: "DNS");
 script_dependencie("dns_server.nasl");
 script_require_ports("DNS/udp/53");
 exit(0);
}


include("byte_func.inc");
include("dns_func.inc");
include("global_settings.inc");


hostname = get_host_name();
if ( hostname =~ "^[0-9.]+" || "." >!< hostname ) exit(0);
domain = ereg_replace(pattern:"^[^.]+\.(.*)$", string:hostname, replace:"\1");
if ( domain == hostname ) exit(0);

dns["transaction_id"] = rand() % 65535;
dns["flags"]          = 0x0010;
dns["q"]              = 1;

packet = mkdns(dns:dns, query:mk_query(txt:dns_str_to_query_txt(domain), type:0x0010, class:0x0001));

port = 53;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(53);
if ( ! soc ) exit(0);
send(socket:soc, data:packet);
r = recv(socket:soc, length:4096);
if ( isnull(r) ) exit(0);
dns = dns_split(r);
if ( isnull(dns) ) exit(0);
if ( dns["an_rr"] != 1 ) exit(0);
spf = dns["an_rr_data_0_data"];
if ( isnull(spf) ) exit(0);
spf = substr(spf, 1, strlen(spf) - 1);
if ( "v=spf" >< spf )
{
 if (report_verbosity)
 {
   security_note(port:53, proto:"udp", extra:'\nThe following SPF records could be extracted for ' + domain + ':\n\n' + spf);
 }
 else security_note(port:53, proto:"udp");
}

