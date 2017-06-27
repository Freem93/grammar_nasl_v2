#
# (C) Tenable Network Security
#

include("compat.inc");

if(description)
{
 script_id(10595);
 script_version ("$Revision: 1.34 $");
 script_cvs_date("$Date: 2017/05/16 19:35:38 $");

 script_cve_id("CVE-1999-0532");
 script_osvdb_id(492);

 script_name(english:"DNS Server Zone Transfer Information Disclosure (AXFR)"); 
 script_summary(english:"Determines if the remote name server allows zone transfers");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote name server allows zone transfers");
 script_set_attribute(attribute:"description", value:
"The remote name server allows DNS zone transfers to be performed. 

A zone transfer lets a remote attacker instantly populate a list of
potential targets.  In addition, companies often use a naming
convention that can give hints as to a servers primary application
(for instance, proxy.example.com, payroll.example.com,
b2b.example.com, etc.). 

As such, this information is of great use to an attacker, who may use
it to gain information about the topology of the network and spot new
targets.");
 script_set_attribute(attribute:"see_also", value:
"https://en.wikipedia.org/wiki/AXFR");
 script_set_attribute(attribute:"solution", value:
"Limit DNS zone transfers to only the servers that need the
information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2001/01/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "1990/01/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2001-2017 Tenable Network Security, Inc.");
 script_family(english: "DNS");

 script_require_ports("Services/dns", 53);
 script_dependencies("dns_server.nasl", "smtpserver_detect.nasl", "ssl_cert_CN_mismatch.nasl", "snmp_sysDesc.nasl", "netbios_name_get.nasl");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("dns_func.inc");
include("byte_func.inc");
include("misc_func.inc");


function ip2ascii()
{
 local_var r;
 r = _FCT_ANON_ARGS[0];
 if ( strlen(r) != 4 ) return NULL;
 return strcat(ord(r[0]), ".", ord(r[1]), ".", ord(r[2]), ".", ord(r[3]));
}

function ipv62ascii()
{
 local_var r;
 local_var i;
 local_var ret;

 r = _FCT_ANON_ARGS[0];
 if ( strlen(r) != 128/8 ) return NULL;
 ret = '';
 for ( i = 0 ; i < strlen(r) ; i += 2 )
 {
  if ( strlen(ret) != 0 ) ret += ':';
  ret += hexstr(substr(r, i, i + 1));
 }
 return ret;
}

function get_domains_from_hostname()
{
 local_var h;
 local_var ret;
 local_var array;
 local_var i;
 local_var str;

 h = _FCT_ANON_ARGS[0];
 if ( h =~ "^[0-9.]+$") return make_list();
 ret = make_list();
 array = split(h, sep:'.', keep:FALSE);
 for ( i = max_index(array) - 1; i >= 0 ; i -- )
 {
  if ( strlen(str) ) str = "." + str;
  str = array[i] + str;
  ret[max_index(ret)] = tolower(str);
 }
 return ret;
}

port = get_kb_item("Services/dns");
if ( ! port ) port = 53;
if ( ! get_port_state(port) ) audit(AUDIT_PORT_CLOSED, port);

# Try to find some domains...

# ..via the host name
domains = get_domains_from_hostname(get_host_name());

# ...via the SMTP banner
kb = get_kb_list('smtp/banner/*');
if ( !isnull(kb) ) foreach banner ( make_list(kb) )
{
 if ( banner =~ "^[0-9]{3} [a-zA-Z0-9.-]+ .*" )
 {
  h = ereg_replace(pattern:"^[0-9]{3} ([a-zA-Z0-9.-]+) .*", replace:"\1", string:banner);
  domains = make_list(domains, get_domains_from_hostname(h));
 }
}

# ...via the SSL cert, SNMP or SMB
foreach kb_label ( make_list('X509/*/altName', 'SNMP/sysName', 'SMB/name' ) )
{
 kb = get_kb_list(kb_label);
 if ( isnull(kb) ) continue;
 foreach hn ( make_list(kb) )
   domains = make_list(domains, get_domains_from_hostname(hn));
}

domains = list_uniq(domains);

if ( max_index(domains) == 0 ) exit(1, "Could not extract a domain name from the KB nor hostname");





foreach domain ( domains )
{
 q = mk_query(type:0x00fc, class:0x0001, txt:dns_str_to_query_txt(domain));
 h = make_array();
 h["transaction_id"] = rand() % 65535;
 h["flags"] = 0;
 h["q"] = 1;

 pkt = mkdns(dns:h, query:q);
 soc = open_sock_tcp(port);
 if (! soc ) audit(AUDIT_NOT_LISTEN, 'DNS' , port);

 pkt = mkword(strlen(pkt)) + pkt;
 send(socket:soc, data:pkt);
 l = recv(socket:soc, length:2);
 if ( strlen(l) != 2 ) 
 {
  close(soc);
  continue;
 }

 l = getword(blob:l, pos:0);
 if ( l > 1024*1024*20 || l < 0 ) 
 {
  close(soc); 
  continue;
 }

 if ( l > 1024*1024 ) l = 1024*1024;

 pkt = recv(socket:soc, length:l);
 close(soc);
 if ( strlen(pkt) != l ) continue;

 dns = dns_split(pkt);
 if ( dns["flags"] & 0x800F != 0x8000 ) continue;

 report = '';

 # Do not display more than 256 hosts per domain
 if ( dns["an_rr"] > 256 ) dns["an_rr"] = 256;


 for ( i = 0 ; i < dns["an_rr"] ; i ++ )
 {
 if (  dns[strcat("an_rr_data_", i, "_class")] == DNS_QCLASS_IN )
 {
  if ( dns[strcat("an_rr_data_", i, "_type")] == 1 ) # A
  {
   ip = ip2ascii(dns[strcat("an_rr_data_", i, "_data")]);
   if ( strlen(ip) ) report = strcat(report, dns[strcat("an_rr_data_", i, "_name")], " has address ", ip, '\n');
   
  }
  else if ( dns[strcat("an_rr_data_", i, "_type")] == 2 ) # NS
  {
   ns = dns_comp_get(str:pkt, offset:dns[strcat("an_rr_data_", i, "_data_offset")]);
   if ( strlen(ns) ) report = strcat(report, dns[strcat("an_rr_data_", i, "_name")], " name server ", ns, '\n');
  }
  else if ( dns[strcat("an_rr_data_", i, "_type")] == 28 ) # AAAA
  {
   ip = ipv62ascii(dns[strcat("an_rr_data_", i, "_data")]);
   if ( strlen(ip) ) report = strcat(report, dns[strcat("an_rr_data_", i, "_name")], " has IPv6 address ", ip, '\n');
  }
  else if ( dns[strcat("an_rr_data_", i, "_type")] == 16 ) # TXT
   {
   if ( strlen(ip) ) report = strcat(report, dns[strcat("an_rr_data_", i, "_name")] , " descriptive text '" , substr(dns[strcat("an_rr_data_", i, "_data")], 1, strlen(dns[strcat("an_rr_data_", i, "_data")]) - 1) , '\'\n');
   }
 else if ( dns[strcat("an_rr_data_", i, "_type")] == 33 ) # SRV
  {
   data = dns[strcat("an_rr_data_", i, "_data")];
   if ( strlen(data) > 6 )
   {
   srv = get_full_query_txt(substr(data, 6, strlen(data) - 1 ));
   if ( strlen(data) ) report = strcat(report, dns[strcat("an_rr_data_", i, "_name")] , " service locator ", getword(blob:data, pos:0), " ", getword(blob:data, pos:2), " ", getword(blob:data, pos:3), " ", srv, '\n');
   }
  }
  }
 }

 if ( strlen(report) )
	complete_report += '\n+ Domain "' + domain + '":\n' + report; 
}



if ( strlen(complete_report) > 0 )
 security_warning(port:53, extra:complete_report);
else
 audit(AUDIT_LISTEN_NOT_VULN, "DNS", port);
 

