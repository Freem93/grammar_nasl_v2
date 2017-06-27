#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11197);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2015/01/21 15:40:55 $");

 script_cve_id("CVE-2003-0001");
 script_bugtraq_id(6535);
 script_osvdb_id(3873);

 script_name(english:"Multiple Ethernet Driver Frame Padding Information Disclosure (Etherleak)");
 script_summary(english:"etherleak check");

 script_set_attribute(attribute:"synopsis", value:"The remote host appears to leak memory in network packets.");
 script_set_attribute(attribute:"description", value:
"The remote host uses a network device driver that pads ethernet frames
with data which vary from one packet to another, likely taken from
kernel memory, system memory allocated to the device driver, or a
hardware buffer on its network interface card.

Known as 'Etherleak', this information disclosure vulnerability may
allow an attacker to collect sensitive information from the affected
host provided he is on the same physical subnet as that host.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?719c90b4");
 script_set_attribute(attribute:"solution", value:"Contact the network device driver's vendor for a fix.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/01/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2015 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 exit(0);
}

include("audit.inc");
include("dump.inc");
include("global_settings.inc");

if ( ! islocalnet() ) exit(0, "The target must be on the same local subnet as the Nessus server.");
if ( TARGET_IS_IPV6 ) exit(0, "Can't test over IPv6.");

function probe()
{
 local_var filter, i, icmp, ip, len, rep, str;

 ip     = forge_ip_packet(ip_p:IPPROTO_ICMP, ip_src:this_host());
 icmp   = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:1, icmp_id:1, data:"x");

 filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host());

 for(i=0;i<3;i++)
 {
 rep = send_packet(icmp, pcap_filter:filter);
 if(rep)break;
 }

 if(rep == NULL)exit(0);
##dump(dtitle: "ICMP", ddata: rep);

 len = get_ip_element(ip:rep, element:"ip_len");
 if(strlen(rep) > len)
 {
 str="";
 for(i=len;i<strlen(rep);i++)
  {
   str = string(str, rep[i]);
  }
  return(str);
 }
 else return(NULL);
}

function ping()
{
 local_var filter, i, icmp, ip, rep;

 ip     = forge_ip_packet(ip_p:IPPROTO_ICMP, ip_src:this_host());
 icmp   = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:1, icmp_id:1, data:crap(data:"nessus", length:254));

 filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host());

 for(i=0;i<3;i++) rep = send_packet(icmp, pcap_filter:filter, pcap_timeout:1);
}

if(islocalhost())exit(0, "Can't test localhost.");


str1 = probe();
ping();
sleep(1);
str2 = probe();

##dump(dtitle: "ether1", ddata: str1);
##dump(dtitle: "ether2", ddata: str2);

if (isnull(str1) || isnull(str2)) exit(0, "There was no padding in one or both packets.");

if (str1 != str2)
{
  str1_0 = str_replace(find:raw_string(0x00), replace:"", string:str1);
  str2_0 = str_replace(find:raw_string(0x00), replace:"", string:str2);
  if (strlen(str1_0) == 0 && strlen(str2_0) == 0) exit(0, "The padding in both packets consists of all NULLs.");

  if (report_verbosity > 0)
  {
    report = '\n' + 'Padding observed in one frame :' +
      '\n' +
      '\n' + '  ' + str_replace(find:'\n', replace:'\n  ', string:hexdump(ddata:str1)) +
      '\n' + 'Padding observed in another frame :' +
      '\n' +
      '\n' + '  ' + str_replace(find:'\n', replace:'\n  ', string:hexdump(ddata:str2));
    report = chomp(report) + '\n';
    security_note(proto:"icmp", port:0, extra:report);
  }
  else security_note(proto:"icmp", port:0);

  set_kb_item(name:"Host/etherleak", value:TRUE);
}
else audit(AUDIT_HOST_NOT, 'affected');
