#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(34325);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2011/05/24 20:37:07 $");

  script_name(english:"Dns2TCP Service Detection");
  script_summary(english:"Sends a DNS2TCP enumerate request");

 script_set_attribute(attribute:"synopsis", value:
"A network service is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote service supports the DNS-to-TCP protocol.  This protocol
hides network traffic protocols by embedding the traffic within
seemingly innocuous DNS queries.  This service can be used to bypass
firewalls or proxies by obfuscating the true protocol within the DNS
protocol." );
 script_set_attribute(attribute:"see_also", value:"http://www.hsc.fr/ressources/outils/dns2tcp/index.html.en" );
 script_set_attribute(attribute:"solution", value:
"Ensure that such services are allowed with respect network policies
and guidelines.  Limit incoming traffic to this port if desired." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/02");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

if ( !thorough_tests ) exit(0);

port = 53;
if (known_service(port:port, ipproto:"udp")) exit(0);
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(0);
close(soc);

host = get_host_name();
if (host == get_host_ip()) exit(0);

subdomains = split(host, sep:string("."), keep:FALSE);

counter = max_index(subdomains);
if ( counter < 1 ) exit(0);

lastoctet = subdomains[counter-1];

domains_to_check = make_list();

if (counter > 2)
{
	base = string(subdomains[counter-2],".",subdomains[counter-1]);
	domains_to_check = make_list(base);
	for (j=counter-3; j>=0; j--)
	{
		base = string(subdomains[j], ".", base);
		domains_to_check = make_list(domains_to_check , base);		
	}
}
else
{
	domains_to_check = make_list(host);
}

foreach hostname (domains_to_check)
{

	cookie = host_dns = svcs = "";

	# build a DNS request
	transaction_id = raw_string(rand() % 256, rand() % 256);
	dns_standard_query = raw_string(1,0);
	questions = raw_string(0,1);
	answers = authority_rrs = additional_rrs = raw_string(0,0);
	pointer = raw_string(0x0c);

	for (i=0; i<12; i++)
	{
        		z = (rand() % 48) + 48;
        		cookie = string(cookie, raw_string(z));
	}



	mylist = split(hostname, sep:string("."), keep:FALSE);

	foreach f (mylist)
        		host_dns = string(host_dns, raw_string(strlen(f)), f);

	host_dns = string(host_dns, raw_string(0));

	query_type = raw_string(0,0x19);        # KEY (Public key)
	query_class = raw_string(0,1);          # IN



	req = string(transaction_id, dns_standard_query, questions, answers, authority_rrs, additional_rrs, pointer, cookie, host_dns, query_type, query_class);

	identifier = string(host_dns, query_type, query_class, raw_string(0xc0, 0x0c), query_type, query_class) ;
	# Send an enumerate request.
	soc = open_sock_udp(port);
	if (!soc) exit(0);

	send(socket:soc, data:req);
	res = recv(socket:soc, length:512);
	close (soc);

	# If it looks like a reply...
	if  ( ( strlen(res) > 20 ) && 
	(cookie >< res) &&
	(host_dns >< res) &&
	(identifier >< res)
	)
	{
		startofsvcs = strstr(res , lastoctet);

		record = 0;
		tmp = "";
		for (mu=strlen(lastoctet); mu<strlen(startofsvcs); mu++)
		{
			if (startofsvcs[mu] =~ "[a-zA-Z0-9/=\+]")
			{
				tmp = string(tmp,startofsvcs[mu]);
				record = 1;
			}
			else
			{
				if (record == 1) # end of base64, decode
				{
					if (strlen(tmp) >= 4)
						svcs = string(svcs, "\n",  base64_decode(str:tmp));
					tmp = "";
					record = 0;
				}
			}
		}

		if (strlen(tmp) >= 4)
			svcs = string(svcs, "\n",  base64_decode(str:tmp));

  		# Register and report the service.
  		register_service(port:port, ipproto:"udp", proto:"dns2tcp");

  		if (report_verbosity)
  		{
    			report = string(
      			"\n",
      			"The remote service supports tunneling the following services :\n",
                        "\n",
      			svcs	
    			);
    			security_note(port:port, proto:"udp", extra:report);
  		}
  		else 
		{
			security_note(port:port, proto:"udp");
		}
	}
}





