#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10443);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/05/06 17:22:01 $");

 script_cve_id(
  "CVE-1999-0077",
  "CVE-2004-0641",
  "CVE-2001-0162",
  "CVE-2001-0163",
  "CVE-2001-0751",
  "CVE-2001-0288",
  "CVE-2001-1104",
  "CVE-2000-0916"
 );
 script_bugtraq_id(107, 670, 3098, 10881);
 script_osvdb_id(199, 4409);

 script_name(english:"TCP/IP Predictable ISN (Initial Sequence Number) Generation Weakness");
 script_summary(english:"TCP SEQ");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to predict TCP/IP Initial Sequence Numbers for the
remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host has predictable TCP sequence numbers.

An attacker may use this flaw to establish spoofed TCP connections to
this host.");
 script_set_attribute(attribute:"solution", value:"Contact your vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1995/01/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/03");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"General");

 script_require_keys("Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if ( TARGET_IS_IPV6 ) exit(1, "This check is not implemented for IPv6 hosts.");

MAX_RETRIES = 5;

function probe(port)
{
 local_var flags, sport, ip, tcp, filter, i, rep, seq;

 ip = forge_ip_packet(
        ip_hl   :5,
        ip_v    :4,
        ip_tos  :0,
        ip_len  :20,
        ip_id   :31338,
        ip_off  :0,
        ip_ttl  :64,
        ip_p    :IPPROTO_TCP,
        ip_src  :this_host()
        );

  sport = (rand() % 60000) + 1024;

  tcp = forge_tcp_packet(ip:ip,
                               th_sport: sport,
                               th_dport: port,
                               th_flags:TH_SYN,
                               th_seq: rand(),
                               th_ack: 0,
                               th_x2: 0,
                               th_off: 5,
                               th_win: 8192,
                               th_urp: 0);
 # Note: these ports look backwards because we're capturing the response
 filter = "tcp and src host " + get_host_ip() + " and src port " + port + " and dst port " + sport;
 for ( i = 0 ; i < MAX_RETRIES ; i ++ )
 {
   rep = send_packet(tcp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:1);
   if ( rep ) break;
 }

 if ( ! rep ) exit(1, "No response to the probe.");

 flags = get_tcp_element(tcp:rep, element:"th_flags");
 if ( flags != (TH_SYN|TH_ACK))
	exit(1, "The server returned an unexpected packet.");
 seq = get_tcp_element(tcp:rep, element:"th_seq");
 return seq;
}

# Get an open port
port = get_host_open_port();
if (isnull(port) || !port) exit(1, "Couldn't find an open port to check.");

for (mu=0; mu<5; mu++)
{

	seqs = make_list();
	for ( i = 0 ; i < 5 ; i ++ )
	{
 		seqs[i] = probe(port:port);
	}

	diffs = make_list();

	for ( i = 1; i < 5 ; i ++ )
	{
	 	diffs[i - 1] = seqs[i] - seqs[i - 1];
 		# Ugly hack, as NASL does not handle unsigned ints
 		if ( diffs[i - 1] < 0 )
			diffs[i - 1] *= -1;
	}

	a = diffs[0];

	for ( i = 1 ; i < 4 ; i ++ )
	{
 		b = diffs[i];
 		if ( a < b )
		{
			c = a;
			a = b;
			b = c;
		}
 		else
		{
			while ( b)
			{
				c = a % b;
				a = b;
				b = c;
			}
		}
	}
	if (mu == 0)
	{
		results = make_list(a);
	}
	else
	{
		results = make_list(results, a);
	}
}


if ( (results[0] == results[1]) &&
	(results[0] == results[2]) &&
	(results[0] == results[3]) &&
	(results[0] == results[4]) )
		security_hole(0);
else
  exit(0, "Host does not appear to be vulnerable.");
