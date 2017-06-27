#
# written by Jon Passki - Shavlik Technologies, LLC <jon.passki@shavlik.com>
# This script is (C) Shavlik Technologies, LLC
# BIG-IP(R) is a registered trademark of F5 Networks, Inc.
# F5 BIG-IP Cookie Persistence Decoder
#

# Changes by Tenable:
# - Revised title, touched up desc, added OSVDB ref (12/16/10)
# Added support for 
#   IPv4 pool members (the original one, the NASL currently detects and decodes this)
#   IPv4 pool members in non-default route domains (my customer had this)
#   IPv6 pool members
#   IPv6 pool members in non-default route domains

include("compat.inc");

if(description)
{
 script_id(20089);
 script_version ("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");

 script_name(english: "F5 BIG-IP Cookie Remote Information Disclosure");
 script_osvdb_id(69862);

 script_set_attribute(attribute:"synopsis", value:
"The remote load balancer suffers from an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be an F5 BIG-IP load balancer. The load
balancer encodes the IP address of the actual web server that it is
acting on behalf of within a cookie. Additionally, information after 
'BIGipServer' is configured by the user and may be the logical name of 
the device. These values may disclose sensitive information, such as 
internal IP addresses and names." );
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a fix." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
# http://support.f5.com/kb/en-us/solutions/public/6000/900/sol6917.html
 script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?18dc4740");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/26");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value: "cpe:/h:f5:big-ip");
 script_end_attributes();

 script_summary(english: "Check F5 BIG-IP(R) Cookie for information disclosure");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Shavlik Technologies, LLC");
 script_family(english: "Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencie("http_version.nasl");
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port)) exit(0);


ips = rds = ports = NULL;
# Number of HTTP connections.
# - gets reset if a new cookie is found.
retries = 5;
# - max number of retries (does not get reset).
max_retries = 10;
flag = 0;

global_var cookie_jar;
pat = make_list();
pat[0] = "^Set-Cookie:.*BIGipServer([^=]+)=([0-9]+)\.([0-9]+)\.([0-9]+)";
pat[1] = "Set-Cookie:.*BIGipServer([^=]+)=rd([0-9]+)o00000000000000000000ffff([0-9a-z]{8})o([0-9]+)";
pat[2] = "^Set-Cookie:.*BIGipServer([^=]+)=vi([0-9a-zA-Z]+)\.([0-9]+)";
pat[3] = "^Set-Cookie:.*BIGipServer([^=]+)=rd([0-9]+)o([0-9a-zA-Z]+)o([0-9]+)";

# nb: IP "a.b.c.d" is encoded as "d*256^3 + c*256^2 + b*256 + a".
function decodeIpv4(enc_ip) 
{
  local_var dec_ip;
  dec_ip = string(
    ( enc_ip & 0x000000ff)      , ".",
    ((enc_ip & 0x0000ffff) >> 8), ".",
    ((enc_ip & 0x00ffffff) >> 16), ".",
    ((enc_ip >> 24) & 0xff)
  );
  debug_print("ip: ", enc_ip, " -> ", dec_ip, ".");

  return dec_ip;
}

function decodePort(enc_port) 
{
  local_var dec_port;
  # nb: port is merely byte-swapped.
  dec_port = (enc_port & 0x00ff) * 256 + (enc_port >> 8);
  debug_print("port: ", enc_port, " -> ", dec_port, ".");

  return dec_port;
}

function decodeIPv4Hex(enc_ip)
{
  local_var dec_ip, oct, match;
  dec_ip = '';
  while(match = eregmatch(pattern:'([0-9a-z]{2})([0-9a-z]*)', string:enc_ip))
  {
    enc_ip=match[2];
    oct = hex2dec(xvalue:match[1]);
    dec_ip +=  oct;
    if(strlen(match[2]) > 0) dec_ip +='.';
  }
  return dec_ip;
}
function ipv6(ip)
{
  local_var value, oct, match;
  value = ereg_replace(pattern:"([0-9a-zA-Z]{4})(?!$)", replace:"\1:", string:ip);
  value = ereg_replace(pattern:"(:0000)", replace:":", string:value);
  value = ereg_replace(pattern:"[:]{2,}", replace:"::", string:value);
  return value;
}

function splitCookie(cookie) 
{
  local_var value;
  cookie = cookie[0];
  value = split(cookie,sep:' ');
  value = value[1];
  cookie_jar[value]++;
  debug_print("cookie: ", value, ".");
  return value;
}

while(retries-- && max_retries--) {
  # Get a cookie.
  soc = http_open_socket(port);
  if ( ! soc && flag == 0 ) exit(0);
  else if( ! soc )  {
	report_error = 1;
	break;
    }
  flag ++;
  req = http_get(item:"/", port:port); 	 
  send(socket:soc, data:req); 	 
  http_headers = http_recv_headers2(socket:soc); 	 
  http_close_socket(soc);

  # If this cookie is replayed in subsequent requests,
  # the load balancer will have an affinity with the back end.
  # This might be a good knowledge base entry.

  if(matches = egrep(pattern:"Set-Cookie:.*BIGipServer", string:http_headers))
  {
    foreach match (split(matches)) {
     dec_port = dec_ip = rd = NULL;
      match = chomp(match);
		# IPv4 Pool Members
        if(cookie = eregmatch(pattern:pat[0], string:match))
        {
          this_cookie = splitCookie(cookie:cookie);
          dec_ip = decodeIpv4(enc_ip:cookie[2]);
          # nb: port is merely byte-swapped.
          dec_port = decodePort(enc_port:cookie[3]);
        } 
		# IPv4 pool members in non-default route domains     
        else if(cookie = eregmatch(pattern:pat[1], string:match))
        {
          this_cookie = splitCookie(cookie:cookie);
          rd = cookie[2];
          dec_ip = decodeIPv4Hex(enc_ip:cookie[3]);
          dec_port = cookie[4];
        } 
		# IPv6 Pool Members
        else if(cookie = eregmatch(pattern:pat[2], string:match))
        {
          this_cookie = splitCookie(cookie:cookie);
          dec_ip = ipv6(ip:cookie[2]);
          dec_port = decodePort(enc_port:cookie[3]);
        }
		#   IPv6 pool members in non-default route domains
        else if(cookie = eregmatch(pattern:pat[3], string:match))
        {
          this_cookie = splitCookie(cookie:cookie);
          rd = cookie[2];
          dec_ip = ipv6(ip:cookie[3]);
          dec_port = cookie[4];
        } 
      # If the cookie is new....
      if (isnull(ips[this_cookie]) || isnull(ips[this_cookie])) {
      # Decode the cookie.
      # Stash them for later.
        ips[this_cookie] = dec_ip;
        ports[this_cookie] = dec_port;
        rds[this_cookie] = rd;
        # Keep trying to enumerate backend hosts.
        retries = 3;
      }
    } 
    if (isnull(dec_ip) || isnull(dec_port)) {
      report_error = 2;
      break;
    }
  }
  else exit(0, "F5 BigIP Server was not detected on this host.");
}


# Generate a report if we got at least one cookie.
if (this_cookie) {
  if(report_error == 1) 
    report = "
The script failed in making a socket connection to the target system
after a previous connection worked.  This may affect the completeness
of the report and you might wish to rerun this test again on the
targeted system. 
";

  if(report_error == 2)
    report = "
The script failed in finding a BIG-IP cookie on the target system
after a previous cookie was found.  This may affect the completeness
of the report and you might wish to rerun this test again on the
targeted system. 
";

#  report = report + "
#The first column is the original cookie, the second the IP address and
#the third the TCP port:
#";

  foreach cookie (keys(cookie_jar)) {
    report += '\n  Cookie       : ' + cookie + 
              '\n  IP           : ' + ips[cookie] + 
              '\n  Port         : ' + ports[cookie]; 
    if(!isnull(rds[cookie])) report += '\n  Route Domain : ' + rds[cookie];
    report += '\n';
  }

  security_warning(port:port, extra:report);
}
