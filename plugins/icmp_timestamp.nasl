#
# (C) Tenable Network Security, Inc.
#

# References:
# RFC 792


include("compat.inc");

if(description)
{
 script_id(10114);
 script_version ("$Revision: 1.45 $");

 script_cve_id("CVE-1999-0524");
 script_osvdb_id(94);

 script_name(english:"ICMP Timestamp Request Remote Date Disclosure");
 script_set_attribute(attribute:"synopsis", value:
"It is possible to determine the exact time set on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host answers to an ICMP timestamp request.  This allows an
attacker to know the date that is set on the targeted machine, which
may assist an unauthenticated, remote attacker in defeating time-based
authentication protocols.

Timestamps returned from machines running Windows Vista / 7 / 2008 /
2008 R2 are deliberately incorrect, but usually within 1000 seconds of
the actual system time." );

 script_set_attribute(attribute:"solution", value:
"Filter out the ICMP timestamp requests (13), and the outgoing ICMP
timestamp replies (14)." );
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/08/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "1995/01/01");
 script_cwe_id(200);
 script_cvs_date("$Date: 2012/06/18 19:06:15 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Performs an ICMP timestamp request");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2012 Tenable Network Security, Inc.");
 script_family(english:"General");
 
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("network_func.inc");
## include("dump.inc");

# Should be moved to misc_func.inc
function abs()
{
 if (_FCT_ANON_ARGS[0] > 0) return _FCT_ANON_ARGS[0]; else return - _FCT_ANON_ARGS[0];
}

if ( islocalhost() ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);

ip = forge_ip_packet(ip_hl:5, ip_v:4,   ip_off:0,
                     ip_id:9, ip_tos:0, ip_p : IPPROTO_ICMP,
                     ip_len : 20, ip_src : this_host(),
                     ip_ttl : 255);

icmp = forge_icmp_packet(ip:ip,icmp_type : 13, icmp_code:0,
                          icmp_seq : 1, icmp_id : 1);
			  
filter = string("icmp and src host ", get_host_ip(), " and dst host ", this_host(), " and icmp[0:1] = 14");
for(i=0;i<3;i++)
{
 rep = send_packet(icmp, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:3);
 if(rep)
 {
  type = get_icmp_element(icmp:rep, element:"icmp_type");
  code = get_icmp_element(icmp:rep, element:"icmp_code");
  if(type == 14 && code == 0)
  {
   txt = NULL;
   data = get_icmp_element(icmp:rep, element:"data");
   if (data)
   {
    #t1 = ntohl(n: substr(data, 8, 11)) / 1000;

    x1 = ord(data[8]); x2 = ord(data[9]); x3 = ord(data[10]); x4 = ord(data[11]);

# MA 2006-08-15... 2006-09-01
# RFC 792
# If the time is not available in miliseconds or cannot be provided
# with respect to midnight UT then any time can be inserted in a
# timestamp provided the high order bit of the timestamp is also set
# to indicate this non-standard value.
#
# However, there is a bug in Windows: 
# timestamp are not in network order (little endian instead of big endian)
# So the high order bit may sometimes be set

    non_std1 = (x1 & 0x80); non_std4 = (x4 & 0x80);
    txt2 = '';
    # 1000/8 = 125; 256/8 = 32
    if (non_std1)
    {
     t1B = -1;
     txt2 = 'This host returns non-standard timestamps (high bit is set)\n';
     set_kb_item(name: 'ICMP/timestamps/non_standard', value: TRUE);
    }
    else
     t1B = (32 * (256 * (256 * x1 + x2) + x3) + x4 / 8) / 125;

    if (non_std4)
     t1L = -1;
    else
     t1L = (32 * (256 * (256 * x4 + x3) + x2) + x1 / 8) / 125;

     v = localtime(utc: 1);
     t2 = v["sec"] + 60 * (v["min"] + 60 * v["hour"]);

    debug_print(level: 2, 't1B=', t1B,' ; t1L=', t1L, ' ; t2=', t2, '\n');

    e = 0; eB = 0; eL = 0;
    # 24 h = 86400 s ; but sometimes, a leap second is added
    if (t1B >= 0 && t1B < 86401 || t1L >= 0 && t1L < 86401)
    {
     eB = t2 - t1B; eL = t2 - t1L;
     e = NULL;
     # Handle invalid timestamp
     if (t1B > 86400) e = eL;
     else if (t1L > 86400) e = eB;
     else
      if (abs(eB) < abs(eL))
       e = eB;
      else
       e = eL;
    
     if (! isnull(e))
     {
      if (e != eB)
      {
       if (non_std1)
        txt2 = strcat(txt2, 'The ICMP timestamps might be in little endian format (not in network format)\n');
       else
        txt2 = strcat(txt2, 'The ICMP timestamps seem to be in little endian format (not in network format)\n');
       set_kb_item(name: 'ICMP/timestamps/little_endian', value: TRUE);
      }
     
       if (e)
       {
        if (e == 1) s = "";
        else s = "s";
        txt2 = strcat(txt2, 'The difference between the local and remote clocks is ', e, ' second', s, '.\n');
       }
       else
        txt2 = strcat(txt2, 'The remote clock is synchronized with the local clock.\n');
     }
    }
    else if (! non_std1)
     txt2 = strcat(txt2, 'This host returns invalid timestamps (bigger than 24 hours).');
    if (txt2) txt = txt2;
   }
  }
  security_note(protocol:"icmp", port:0, extra: txt);
  exit(0);
 }
}

