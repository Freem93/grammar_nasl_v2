#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);


include("compat.inc");

if (description)
{
  script_id(31422);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2011/03/21 16:24:56 $");

  script_name(english:"Reverse NAT/Intercepting Proxy Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote IP address seems to connect to different hosts
via reverse NAT, or an intercepting proxy is in the way." );
 script_set_attribute(attribute:"description", value:
"Reverse NAT is a technology which lets multiple computers offer
public services on different ports via the same IP address. 

Based on OS fingerprinting results, it seems that different 
operating systems are listening on different remote ports.

Note that this behavior may also indicate the presence of a
intercepting proxy, a load balancer or a traffic shaper." );
 script_set_attribute(attribute:"see_also", value:"http://en.wikipedia.org/wiki/Proxy_server#Intercepting_proxy_server" );
 script_set_attribute(attribute:"solution", value:
"Make sure that this setup is authorized by your security policy" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Determines the remote operating system on each port");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");
  exit(0);
}

#

if ( ! defined_func("bsd_byte_ordering") ) exit(0);
if ( TARGET_IS_IPV6 ) exit(0);
if (  islocalhost() ) exit(0);

function sigdiff()
{
 local_var a, b, i, n;
 local_var cnt;

 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 n = strlen(a);
 cnt = 0;
 if ( strlen(b) < strlen(a) ) n = strlen(b);
 for ( i = 0 ; i < n ; i ++ )
 {
	if ( a[i] != b[i] ) cnt ++;
 }

 if ( strlen(a) > strlen(b) )
	cnt += strlen(a) - strlen(b);
 else if ( strlen(b) > strlen(a))
	cnt += strlen(b) - strlen(a);

 return cnt;
}


include("raw.inc");
include("global_settings.inc");
include("sinfp.inc");

StartTime = unixtime();
EndTime   = StartTime + 30; # Run 30 seconds at max
if ( thorough_tests ) EndTime += 120;
ports = get_kb_list("Ports/tcp/*");
if ( isnull(ports) ) exit(0);
ports = keys(ports);
sig = make_list();
os = make_list();

foreach key ( ports )
{
  port = int(key - "Ports/tcp/");
  t = sinfp(dport:port, no_p3:TRUE);
  if ( unixtime() >= EndTime ) break;
  if ( !isnull(t) ) sig[key] = t;
}


foreach item ( keys(sig) ) 
{
 t = sig[item];
 if ( isnull(t) || isnull(t["signature"]) ) continue;
 if ( !isnull(t["distance"]) ) t["signature"] += ":D" + t["distance"];
 sig2osname[t["signature"]] = t["osname"];
 os[t["signature"]] ++;
 os_by_port[t["signature"]] += '\n - ' + (item - "Ports/tcp/");
 if ( !isnull(t["distance"]) ) os_by_port[t["signature"]] += " (" + t["distance"] + " hops away)";
}

all_different_sigs = sort(keys(os));
for ( i = 1; i < max_index(all_different_sigs) ; i ++ )
{
 osname1 = os_name_split(all_different_sigs[i-1]);
 if ( osname1 != NULL ) osname1 = osname1["os"];
 osname2 = os_name_split(all_different_sigs[i]);
 if ( osname2 != NULL ) osname2 = osname2["os"];
 if (  sigdiff(all_different_sigs[i-1],all_different_sigs[i]) < 2 || (osname1 == osname2) )
  	{
	os[all_different_sigs[i-1]] = NULL;
	os_by_port[all_different_sigs[i]] += os_by_port[all_different_sigs[i-1]];
	sig2osname[all_different_sigs[i]] += sig2osname[all_different_sigs[i-1]];
	}
}

if ( max_index(keys(os)) > 1 )
{
 report = NULL;
 flag = 0;
 foreach item ( keys(os) ) 
 { 
  if ( os[item] == NULL ) continue;
  name = os_name_split(sig2osname[item]);
  if ( name["os"] == NULL ) continue;
  flag ++;
  report += "+ On the following port(s) : ";
  report += os_by_port[item] + '\n\nThe operating system was identified as :\n\n' + name["os"] + '\n\n';
 }
 if ( flag > 1 ) {
	set_kb_item(name:"Host/ReverseNAT", value:TRUE);
	security_note(port:0, extra:report);
 }
}
