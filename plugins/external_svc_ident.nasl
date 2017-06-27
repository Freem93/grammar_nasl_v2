#
# (C) Tenable Network Security, Inc.
#

# We could do this job in amap.nasl or nmap.nasl, but as those
# plugins must be signed to be "trusted", we don't want to change them often


include("compat.inc");

if (description)
{
 script_id(14664);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2011/03/11 21:52:32 $");

 script_name(english: "External Scanner Service Identification");

 script_set_attribute(attribute:"synopsis", value:
"This plugin performs service detection." );
 script_set_attribute(attribute:"description", value:
"This plugin registers services that were identified by external
scanners (amap, nmap, etc...). 

It does not perform any fingerprinting by itself." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/05");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_copyright(english: "This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_category(ACT_GATHER_INFO);
 script_family(english: "General");
 script_summary(english: "Register services that were identified by amap or nmap");
 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

amapcvt['http'] = 'www';
amapcvt['http-proxy'] = 'http_proxy';
amapcvt['rsyncd'] = 'rsync';
amapcvt['x-windows'] = 'X11';
amapcvt['ms-distribution-transport'] = 'msdtc';

nmapcvt['http'] = 'www';
nmapcvt['http-proxy'] = 'http_proxy';

foreach ipp (make_list('tcp', 'udp'))
{
 ports = get_kb_list('Ports/'+ipp+'/*');
 if (! isnull(ports))
 {
  foreach port  (keys(ports))
  {
   s = get_kb_item('Amap/'+ipp+'/'+port+'/Svc');
   banner = get_kb_item('Amap/'+ipp+'/'+port+'/FullBanner');
   if (!banner)
    banner = get_kb_item('Amap/'+ipp+'/'+port+'/PrintableBanner');
   svc = NULL;

   if (s && s != 'ssl' && s != 'unindentified')
   {
    svc = amapcvt[s];
    if (! svc)
     if (match(string: s, pattern: 'dns-*'))
      svc = 'dns';	# not used yet  
     else if (match(string: s, pattern: 'http-*'))
      svc = 'www';
     else if (match(string: s, pattern: 'nntp-*'))
      svc = 'nntp';
     else if (match(string: s, pattern: 'ssh-*'))
      svc = 'ssh';
     else
      svc = s;
     # Now let's check some suspicious services
     if (s == 'echo' && ipp == 'tcp')
     {
       soc = open_sock_tcp(port);
       if (! soc)
         svc = NULL;
       else
       {
         str = rand_str() + '\n';
         send(socket: soc, data: str);
         b = recv(socket: soc, length: 1024);
         if (b != str) svc = NULL;
         close(soc);
       }
     }
   }
   else
   {
    s = get_kb_item('NmapSvc/'+ipp+'/'+port);
    if ( s ) 
    {
     svc = amapcvt[s];
     if (! svc)	# we probably need some processing...
      svc = s;
    }
   }
   if (svc)
    register_service(port: port, proto: svc, ipproto: ipp);
   else if (b)
    set_unknown_banner(port: port, banner: b, ipproto: ipp);
  }
 }
}

