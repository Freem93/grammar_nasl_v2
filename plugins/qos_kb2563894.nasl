#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56044);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/05/26 15:47:04 $");

  script_cve_id("CVE-2011-1871", "CVE-2011-1965");
  script_bugtraq_id(48987, 48990);
  script_osvdb_id(74482, 74483);
  script_xref(name:"MSFT", value:"MS11-064");

  script_name(english:"MS11-064: Vulnerabilities in TCP/IP Stack Could Allow Denial of Service (2563894) (uncredentialed check)");
  script_summary(english:"Checks for the Differential Service Code Point (DSCP) value in reply.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is susceptible to denial of service attacks.");
  script_set_attribute(attribute:"description", value:
"The TCP/IP stack in use on the remote Windows host is potentially
affected by a denial of service vulnerability. By sending a request
with a specially crafted URL, an unauthenticated, remote attacker may
be able to cause the affected host to stop responding and
automatically reboot if it is serving web content and has URL-based
QoS (Quality of Service) enabled.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-064");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 7 and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "webmirror.nasl","os_fingerprint.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("http.inc");



##
# get the Differential Service Code Point (DSCP) in the reply packet for an URL reqeust
#
# @param url - requested URL path
#
# @return DSCP value, or NULL
#
##
function get_dscp(url, port)
{
  local_var req,res, filter, dscp;
  local_var ret, soc,shost, sport, dhost, dport;

  soc = open_sock_tcp(port);
  if(! soc) exit(0, 'Failed to open port '+port+'.');


  shost = this_host();
  sport = get_source_port(soc);

  dhost = get_host_ip();
  dport = port;

  req = 'GET '+url+ ' HTTP/1.1\r\n' +
        'Host: ' + dhost + '\r\n' +
        'Connection: keep-alive\r\n' +
        '\r\n';



  # first reply packet with data
  filter = 'tcp' +
         ' and src host ' + dhost + ' and src port '+dport+
         ' and dst host ' + shost + ' and dst port '+sport+
         ' and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)';


  res = send_capture(socket:soc, data: req,pcap_filter:filter);

  if(isnull(res))return NULL;

  dscp = getbyte(blob:res, pos:1) >> 2;
  #display('port:'+port+',dscp:'+dscp+',transport:'+get_port_transport(port)+',url:'+url+'\n');

  return dscp;
}

##
# gather a list (some) of URLs (diretories) found by mirror.nasl
#
# @param port - http port
#
# @return url list
#
#
##
function gather_url_list(port)
{
  local_var url_list,list;

  url_list = make_list();

  #
  # add directories found
  #
  list = get_kb_list('www/'+ port+ '/content/directories');
  if(! isnull(list))
    url_list = make_list(url_list, list);

  #
  # other possible sources
  #

  return url_list;
}


#
# Main
#

if ( TARGET_IS_IPV6 ) exit(0, 'The target host is IPv6.');
if(islocalhost())     exit(0, 'The target host is the local host.');

# check for OS
# URL-based QoS is only available on computers running Windows 7 or 2008 R2
os = get_kb_item("Host/OS");
if(! isnull(os))
{
  if("Windows" >!< os) exit(0, 'Remote host OS is not Windows.');

  #
  # TODO:
  #   add future Windows versions
  if(! ("7" >< os || "2008 R2" >< os))
    exit(0, 'Remote host OS is not Windows 7 or Windows Server 2008 R2.');
}
else
  exit(0, 'Unable to determine remote host OS.');


# check for IIS
# only IIS supports QoS
port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(! isnull(banner))
{
  if("IIS" >!< banner)
    exit(0, 'The HTTP server on port '+port+ ' does not appear to be Microsoft IIS.');
}
else
  exit(0, 'Failed to get http banner for port ' + port+'.');


if (report_paranoia < 2) audit(AUDIT_PARANOID);


url_list = gather_url_list(port:port);


#
# find a URL-based policy with DSCP >0 and  the "Include subdirectories and files" option enabled
#
# if the reply packet for some URLs has a DSCP>0, and some with DSCP=0
# it probably means a URL-based QoS policy has been enabled.
#
test_url = NULL;
count = 0;
misses = 0;
foreach url (url_list)
{

  dscp = get_dscp(url:url, port:port);
  if(isnull(dscp)) continue;

  # test up to 100 URLs
  if(count++ > 100) break;

  if(dscp > 0)
  {
    # check for "Include subdirectories and files"
    subdir_url = url +'/PPP/QQQ';
    dscp = get_dscp(url:subdir_url, port:port);
    if(dscp > 0)
    {
      if(misses >0)
      {
        test_url = url;
        break;
      }
    }

  }
  else if(dscp == 0)  misses++;
}


if(isnull(test_url))
  exit(0, 'Could not find a suitable URL on the web server running on port '+port+' for testing.');


need = 0x4000 - strlen(test_url);

while(need >0)
{
  if(need > 255) len = 255;
  else           len = need -1;
  test_url += '/'; need -= 1;
  test_url +=crap(data:'A',length:len); need -= len ;
}

#
# check whether the webserver supports longer URL length
#
http_disable_keep_alive();
res = http_send_recv3(method:'GET',port:port, item:test_url, exit_on_fail:TRUE);

if(res[0] =~"HTTP/1\..* 414")
  exit(0, 'The web server on port '+port+' does not support a URL length of '+strlen(test_url)+'.');

#
# fill the kernel lookaside nonpaged memory with a URL that will most likely fail
# a URL match test. This is done so because the same lookaside memory might be re-used
# if the allocation length is less than 256 bytes in unicode. This memory might contain
# a matched URL from runs of the URL-based QoS policy searcher above.
#
# allocation length is computed as:
# alloc_len = (pPath - pUrl) + // distance btw the url path and the beginning of the url
#                              // ie. http://some.host.name.com/url_path
#
#             url_path_len +
#             sid_len; // seen 0x20
#
# if we specify url_path_len = 0x4000, it will be 0x8000 bytes in unicode,
# the vulnerable function doubles the url_path_len and becomes 0x10000, because
# url_path_len is a unsigned short, it wraps to 0.
#
#
# the end result is that the path to compare with the one in the policy is:
#
# UNICODE_STRING url_path
#
# url_path.length = url_path.maxlength = 0x8000;
# url_path.buffer = some_unitialized_memory
#
#
http_send_recv3(method:'GET',port:port, item:'/'+rand_str(length:20), exit_on_fail:TRUE);

dscp = get_dscp(url:test_url, port:port);
if(isnull(dscp))
  exit(1, 'Could not get the DSCP value in the reply packet.');

if(dscp == 0)
  security_hole(port:port);
else
  exit(0, 'The host appears to be patched.');

