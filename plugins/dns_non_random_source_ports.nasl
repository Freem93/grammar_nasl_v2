#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(33447);
  script_version ("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2008-1447");
  script_bugtraq_id(30131);
  script_osvdb_id(
    46776,
    46777,
    46786,
    46836,
    46837,
    46916,
    47232,
    47233,
    47510,
    47546,
    47588,
    47660,
    47916,
    47926,
    47927,
    48186,
    48244,
    48256,
    53530,
    53917
  );
  script_xref(name:"CERT", value:"800113");
  script_xref(name:"IAVA", value:"2008-A-0045");
  script_xref(name:"EDB-ID", value:"6122");
  script_xref(name:"EDB-ID", value:"6123");
  script_xref(name:"EDB-ID", value:"6130");
  # OSVDB split by vendor, 20 results as of 7/1/09. Including 6 higher profile vendors above.

  script_name(english:"Multiple Vendor DNS Query ID Field Prediction Cache Poisoning");
  script_summary(english:"Determines if the remote DNS server uses random source ports when making queries.");

  script_set_attribute(attribute:"synopsis", value:
"The remote name resolver (or the server it uses upstream) is affected
by a DNS cache poisoning vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote DNS resolver does not use random ports when making queries
to third-party DNS servers. An unauthenticated, remote attacker can
exploit this to poison the remote DNS server, allowing the attacker to
divert legitimate traffic to arbitrary sites.");
  script_set_attribute(attribute:"see_also", value:"https://www.cnet.com/news/massive-coordinated-dns-patch-released/");
  script_set_attribute(attribute:"see_also", value:"http://www.theregister.co.uk/2008/07/21/dns_flaw_speculation/");
  script_set_attribute(attribute:"solution", value:
"Contact your DNS server vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/09");
  
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "DNS");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  
  script_dependencie("bind_query.nasl");
  script_require_keys("DNS/recursive_queries");
  exit(0);
  }

include("global_settings.inc");
include("audit.inc");
include("byte_func.inc");
include("dns_func.inc");
include("misc_func.inc");
include("spad_log_func.inc");

port = 53;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

MIN_SAMPLES = 4;
NUM = 4;
HARD_LIMIT = 50;

function abs()
{
 local_var x;
 x = _FCT_ANON_ARGS[0];
 if ( x > 0 ) return x;
 return 0 - x;
}

totCount = 0;
per_ip = make_array();

for ( i = 0 ; i < NUM ; i ++ )
{
  totCount ++;
  req["transaction_id"] = rand() % 65535;
  req["flags"] = 0x0100;
  req["q"]     = 1;
  packet = mkdns(dns:req, query:mk_query(txt:dns_str_to_query_txt(rand_str(length:8, charset:"abcdefghijklmnopqrstuvwxyz")  + "-" + i + ".t.nessus.org."), type:0x0010, class:0x0001));
  soc = open_sock_udp(53);
  send(socket:soc, data:packet);
  r = recv(socket:soc, length:4096);
  close(soc);
  if ( ! r )
    exit(1, "Failed to receive DNS response from socket.");

  r = dns_split(r);
  res = r["an_rr_data_0_data"];
  if ( ! res )
    exit(1, "DNS result not received.");

  if( strlen(res) < 2  )
    exit(1, "DNS result length < 2.");

  res = substr(res, 1, strlen(res) - 1);
  if ( res !~ "^[0-9.]+,[0-9]+")
    exit(1, "DNS results don't conform to IP address regex.");

  array = split(res, sep:",", keep:FALSE);
  responses_ports = per_ip[array[0]];
  if ( isnull(responses_ports) )
  {
	  responses_ports = make_list();
 	  if ( max_index(keys(per_ip)) > 0 ) NUM += 4;
	}
  responses_ports[max_index(responses_ports)] = int(array[1]);
  per_ip[array[0]] = responses_ports;

  if ( totCount > HARD_LIMIT ) break;
}

# debug logging
foreach dns_server ( keys(per_ip) )
{
  responses_ports = per_ip[dns_server];
  spad_log(message:"DNS Server " + dns_server + " response ports : " + join(responses_ports, sep:","));
}

buggy_dns_servers = make_array();
foreach dns_server ( keys(per_ip) )
{
  responses_ports = per_ip[dns_server];
  if ( max_index(responses_ports) >= MIN_SAMPLES )
   {
    flag = 0;
    for ( i = 1 ; i < max_index(responses_ports) && flag == 0; i ++ ) {
      if ( abs(responses_ports[i - 1] - responses_ports[i]) >= 20 )
        flag = 1;
    }
    if ( flag == 0 )
    {
     buggy_dns_servers[dns_server] = responses_ports;
    }
   }
}

if ( max_index(keys(buggy_dns_servers)) > 0 )
{
 report = "
The remote DNS server uses non-random ports for its
DNS requests. An attacker may spoof DNS responses.

List of used ports :
";
  foreach dns_server ( keys(buggy_dns_servers) )
  {
    report += '\n+ DNS Server: ' + dns_server + '\n';
    responses_ports = buggy_dns_servers[dns_server];
    for ( i = 0 ; i < max_index(responses_ports) ; i ++ )
	{
	  report += '|- Port: ' + responses_ports[i] + '\n';
	}
  }

 security_hole(port:53, proto: "udp", extra: report);
}
else
{
  audit(AUDIT_LISTEN_NOT_VULN, "DNS", port);
}
