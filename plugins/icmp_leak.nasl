#
# (C) Tenable Network Security, Inc.
#
# Thanks to Philippe Biondi <biondi@cartel-securite.fr> for his help.
#
# See the Nessus Scripts License for details
#
# Ref: http://www.cartel-securite.fr/pbiondi/adv/CARTSA-20030314-icmpleak
# Ref: VU#471084 (http://www.kb.cert.org/vuls/id/471084)
#
# Refs:
#  Date: Mon, 9 Jun 2003 08:56:55 +0200 (CEST)
#  From: Philippe Biondi <biondi@cartel-securite.fr>
#  To: vuln-dev@securityfocus.com, <full-disclosure@lists.netsys.com>,
#        <bugtraq@securityfocus.com>
#  Subject: Linux 2.0 remote info leak from too big icmp citation


include("compat.inc");

if(description)
{
 script_id(11704);
 script_version ("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
 script_cve_id("CVE-2003-0418");
 script_osvdb_id(2173);
 script_xref(name:"CERT", value:"471084");

 script_name(english:"Linux Kernel IP Stack ICMP Error Response Arbitrary Memory Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is vulnerable to an 'icmp leak' of
potentially confidential data.  That is, when the 
host generates an ICMP error packet other than 
'destination unreachable', the  error packet is 
supposed to only contain the original message or 
a portion of the original message. 

Due to a bug in the remote TCP/IP stack, these ICMP
error messages will also contain fragments of the content 
of the remote kernel memory.

An attacker may use this flaw to remotely sniff what is going into
the host's memory, especially network packets that it sees, and
obtain useful information such as POP passwords, HTTP authentication
fields, and so on." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7b08d5e" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9eeb958c" );
 script_set_attribute(attribute:"solution", value:
"Contact your vendor for a fix. If the remote host is running
Linux 2.0, upgrade to Linux 2.0.40." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ac5b22d" );





 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/09");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "icmpleak check";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 family["english"] = "Misc.";
 script_family(english:family["english"]);
 script_dependencies("os_fingerprint.nasl");
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}




#
# The script code starts here
# 

include('global_settings.inc');


if ( TARGET_IS_IPV6 ) exit(0);
if(islocalhost())exit(0);
if ( !thorough_tests) exit(0);

os = get_kb_item("Host/OS");
if ( os && !egrep(pattern:"Linux 2\.[0-2]", string:os) ) exit(0);


# Sends a fragmented ping packet
function send_frag_ping()
{
	local_var filter, i, ip, icmp, rep;

	ip = forge_ip_packet(ip_hl : 5, ip_v : 4, ip_tos: 0, ip_len : 46,
ip_id: rand(), ip_off: IP_MF, ip_ttl: 64, ip_p : IPPROTO_ICMP, ip_src : this_host(), ip_dst:get_host_ip());

	icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:0, icmp_id:0, data:crap(length:18, data:"X"));

	filter = string("icmp and src ", get_host_ip(), " and icmp[0] = 11 and icmp[1] = 1 and icmp[36]=88 and icmp[37]=88");
	
	for(i=0;i<5;i++)
	{
	 send_packet(icmp, pcap_active:FALSE);
	 sleep(1);
	}
	
	rep = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:31);
	if(rep) return(rep);
	else return NULL;
}


rep = send_frag_ping();
if( rep != NULL )
{
 start = 20 + 8 + 28;
 end   = strlen(rep);
 for(i = start ; i < end ; i ++)
 {
  if(rep[i] != "X" )
  {
    security_warning(proto:"icmp", port:0);
    exit(0);
  }
 }
}
