#
# (C) Tenable Network Security, Inc.
#

# @PREFERENCES@

# Starting with Nessus 3.1.5, this script replaces find_service.nes

# Check if this version of nessusd is too old
if ( NASL_LEVEL < 3203 ) exit(0);

include("compat.inc");

if (description)
{
 script_id(22964);
 script_version("$Revision: 1.156 $");
 script_cvs_date("$Date: 2017/05/26 16:06:48 $");

 script_name(english:"Service Detection");
 script_summary(english:"Sends 'GET' to unknown services and looks at the answer.");

 script_set_attribute(attribute:"synopsis", value:
"The remote service could be identified.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to identify the remote service by its banner or by
looking at the error message it sends when it receives an HTTP
request.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Service detection");

 script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

 script_timeout(0);
 script_add_preference(name:"Test SSL based services", type:"radio", value:"Known SSL ports;All;None");
 script_dependencie(
  "dcetest.nasl",
  "rpcinfo.nasl",
  "pjl_detect.nasl",
  "dont_scan_printers.nasl",
  "dont_scan_printers2.nasl",
  "zend_server_java_bridge_code_exec.nasl",
  "veritas_vxsvc_detect.nbin",
  "find_smtp.nasl",
  "emc_autostart_ftagent_detect.nbin",
  "mongodb_detect.nasl",
  "scada_cip_list_identity.nbin"
 );

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");
include("ssl_funcs.inc");

if ( get_kb_item("global_settings/disable_service_discovery")  ) exit(0, "Service discovery has been disabled.");

#
# Global variables and constants
#
global_var g_sock, g_transport_state, g_sock_state, g_banners, g_timestamps;
global_var g_port_pool, g_port_pool_idx, g_port_pool_max, state_to_transport, g_methods;
global_var g_ssl_ports, g_ssl_ports_H;

global_var g_ssl_ports_to_try, g_ssl_ports_to_try_idx;

TLSv1_1_AVAILABLE = FALSE;
TLSv1_2_AVAILABLE = FALSE;

if (ENCAPS_TLSv1_1)
  TLSv1_1_AVAILABLE = TRUE;
if (ENCAPS_TLSv1_2)
  TLSv1_2_AVAILABLE = TRUE;

E_STATE_TLSv1       = 1;
E_STATE_SSLv3       = 2;
E_STATE_SSLv23      = 3;
E_STATE_SSLv2       = 4;
E_STATE_TLSv11      = 5;
E_STATE_TLSv12      = 6;
E_STATE_TLS_HELLO   = 7;
E_STATE_SSL3_HELLO  = 8;
E_STATE_SSL2_HELLO  = 9;
E_STATE_IP          = 10;

E_STATE_SSL_START = E_STATE_TLSv1;

TIMEOUT	 = 5;
SPONTANEOUS_TIMEOUT = 2;
CONNECT_TIMEOUT = 4;
MAX_SIMULT_CONNECTIONS = 5;

S_STATE_CONNECTING = 1;
S_STATE_READING    =  2;
S_STATE_READING_W_GET = 3;
S_STATE_DONE	      = 4;

SSL_CONNECT_NONE = 0;
SSL_CONNECT_ALL = 1;
SSL_CONNECT_KNOWN = 2;

SSL_PORT_TO_CONNECT = SSL_CONNECT_KNOWN;

state_to_transport[E_STATE_SSLv23] = ENCAPS_SSLv23 | ENCAPS_DISABLE_TLSv1_1 | ENCAPS_DISABLE_TLSv1_2;
state_to_transport[E_STATE_SSLv2] = ENCAPS_SSLv2;
state_to_transport[E_STATE_TLSv1] = ENCAPS_TLSv1;
state_to_transport[E_STATE_SSLv3] = ENCAPS_SSLv3;
state_to_transport[E_STATE_TLSv11] = ENCAPS_TLSv1_1;
state_to_transport[E_STATE_TLSv12] = ENCAPS_TLSv1_2;
state_to_transport[E_STATE_TLS_HELLO] = ENCAPS_IP;
state_to_transport[E_STATE_SSL3_HELLO] = ENCAPS_IP;
state_to_transport[E_STATE_SSL2_HELLO] = ENCAPS_IP;
state_to_transport[E_STATE_IP]    = ENCAPS_IP;

g_ssl_ports = make_list(
  261,    # Nsiiops
  443,    # HTTPS
  446,    # Openfiler's management interface
  448,    # ddm-ssl
  465,    # SMTPS
  563,    # NNTPS
  585,    # imap4-ssl
  614,    # SSLshell
  636,    # LDAPS
  684,    # Corba IIOP SSL
  695,    # IEEE-MMS-SSL
  902,    # VMWare Auth Daemon
  989,    # FTPS data
  990,    # FTPS control
  992,    # telnets
  993,    # IMAPS
  994,    # IRCS
  995,    # POP3S
  1032,   # HP Server Automation (twisted web interface)
  1241,   # Nessus
  1243,   # PVS Proxy
  1311,   # Dell OpenManage
  1950,   # Tivoli Security Configuration Manager agent
  2010,   # IBM HTTP Server administration SSL port
  2050,   # Domino
  2161,   # APC UPS Power Monitoring Agent
  2224,   # Pacemaker PCSD Service
  2381,   # Compaq Web Management
  2456,   # SGMI (Remote firewall management)
  2478,   # SecureSight Authentication Server
  2479,   # SecureSight Event Logging Server
  2482,   # Oracle GIOP SSL
  2484,   # Oracle TTS SSL
  2679,   # Sync Server SSL
  2738,   # HP DDMI
  3037,   # Novell File Reporter Agent
  3077,   # Orbix 2000 Locator SSL
  3078,   # Oribx 2000 Locator SSL
  3220,   # Juniper Junos XML protocol server (over SSL)
  3269,   # Microsoft Global Catalog w/ LDAP/SSL
  3389,   # Microsoft Remote Desktop
  3424,   # Xware xTrm Communication Protocol over SSL (xtrms)
  3471,   # jt400 SSL
  3661,   # IBM Tivoli Directory Service using SSL
  3780,   # Nexpose
  3790,   # Metasploit HTTPS Server
  3994,   # IIS deployment manager
  4031,   # UUCP over SSL
  5007,   # WSM Server SSL
  5061,   # SIP over TLS
  5443,   # IBM WebSphere Commerce Payments secure server
  5480,   # VMware vRealize Automation and SolarWinds Virtualization Manager
  5556,   # Oracle WebLogic Node Manager
  5666,   # Nagios Remote Plugin Executor (NRPE)
  5671,   # Advanced Message Queueing Protocol -- SSL
  5783,   # 3PAR Management Service
  6697,   # IRC/SSL
  6789,   # Sun Java Web Console
  7002,   # WebLogic
  7004,   # RSA Secure Logon
  7071,   # Zimbra Collaboration Server
  7135,   # IBM Tivoli Access Manager runtime env -- SSL
# nb: IANA lists a different service assigned to TCP 7101
# 7101,   # Oracle Enterprise Manager Admin Server (HTTPS)
  7183,   # Cloudera Manager
  7301,   # Oracle Enterprise Manager Cloud Control Managed Server (HTTPS)
  7403,   # Oracle Enterprise Manager Grid Control Node Manager (HTTPS)
  7700,   # Bosch Security System Ethernet Connection Module
  8000,   # Tenable Appliance / IBM WebSphere Commerce Accelerator
  8002,   # IBM WebSphere Commerce Server Admin Console
  8004,   # IBM WebSphere Commerce Server Organization Administration Console
  8006,   # IBM WebSphere Commerce preview
  8012,   # Citrix XenServer Workload Balancer
  8082,   # BlueCoat ProxySG Console
  8089,   # Splunk management port
  8139,   # Puppet agent
  8140,   # Puppet master
  8333,   # VMware
  8443,   # Tomcat
  8444,   # McAfee ePolicy Orchestrator
  8445,   # Symantec SEPM
  8834,   # Nessus 4.2
  8835,   # PVS 4.0
  8880,   # IBM WebSphere Application Server SOAP connector
  9043,   # IBM WebSphere Application Server administrative console secure port
  9390,   # OpenVAS Manager
  9391,   # OpenVAS Scanner
  9392,   # Greenbone Security Assistant
  9393,   # OpenVAS Administrator
  9443,   # WebSphere internal secure server
  9090,   # HP iNode Management Center
  10000,  # Webmin+SSL
  13841,  # HP VSA hydra 10.0
  10443,  # McAfee Email Gateway
  18443,  # MySQL Enterprise Monitoring
  19201,  # SilPerformer agent
  40007,  # AlienVault OSSIM SOAP
  40011,  # AlienVault OSSIM REST
  42966,  # HP Remote Graphics
  50000,  # HP Insight Software
  54345,  # HP Load Runner
  54984,  # WebYaST Web Client
  63002,  # HP Smart Update Manager
  65443   # McAfee LinuxShield nailsd
);

#
# Initialize the variables
#

function globals_reset()
{
 g_sock_state = make_list();
 g_sock = make_list();
 g_transport_state = make_list();
 g_banners = make_list();
 g_timestamps = make_list();
 g_methods = make_list();
 g_port_pool_max = 0;
 g_port_pool_idx = 0;
}

function globals_init()
{
 globals_reset();
 g_ssl_ports_to_try_idx = 0;
 g_ssl_ports_to_try = make_list();
}

#----------------------#
# Service recognition  #
#----------------------#

function SSL_hello(port)
{
 local_var ver;
 local_var cipherspec, cspeclen;
 local_var chello;
 local_var hello_done;
 local_var data;
 local_var rec;
 local_var cipher;
 local_var n;
 local_var soc;
 local_var state;
 local_var exts, exts_len;
 local_var rec_ver;

 soc = g_sock[port]; 
 state = g_transport_state[port];

 cipherspec = NULL;
 ver = NULL;

 # Detect SSLv3+, TLS servers should support backward compatibility 
 if(state != E_STATE_SSL2_HELLO)
 { 
   foreach cipher (sort(keys(ciphers)))
   {
     if('TLS1' >< cipher)
     {
       cipherspec +=  ciphers[cipher];
     }
   }
   cipherspec += raw_string(0x00, 0xff);
   cspeclen = mkword(strlen(cipherspec));

   rec_ver = raw_string(3,1);
   exts = tls_ext_ec() + tls_ext_ec_pt_fmt();
   exts_len  = mkword(strlen(exts));

   if(state == E_STATE_SSL3_HELLO)
   {
    rec_ver = raw_string(3,0);
    exts = exts_len = NULL;
   }
   chello = client_hello(v2hello:FALSE, version: rec_ver,
                        cipherspec : cipherspec,
                        cspeclen   : cspeclen,
                        extensions : exts,
                        extensionslen: exts_len,
                        maxver     : raw_string(3,3) 
                        );
   send(socket:soc, data:chello);
   hello_done = FALSE;
   n = 0;
   while ( ! hello_done )
   {
    if ( n++ > 64 ) return -1;
    data = recv_ssl(socket:soc);
    if ( isnull(data) ) return -2;

    # Server Hello 
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO
    );
    if ( !isnull(rec) ) 
    {
      if( !isnull(rec['handshake_version']))
        ver = rec['handshake_version'];
      else
        return -3;
    }
    # Server Hello Done.
    rec = ssl_find(
      blob:data,
      'content_type', SSL3_CONTENT_TYPE_HANDSHAKE,
      'handshake_type', SSL3_HANDSHAKE_TYPE_SERVER_HELLO_DONE
    );

    if ( !isnull(rec) ) hello_done = TRUE;
   }

  return ver;
 }
 # Detect SSLv2 server
 else
 {
   foreach cipher (sort(keys(ciphers)))
   {
     if('SSL2_' >< cipher)
     {
       cipherspec +=  ciphers[cipher];
     }
   }
   cspeclen = mkword(strlen(cipherspec));

   chello = client_hello(
      version    : raw_string(0,2),
      cipherspec : cipherspec,
      cspeclen   : cspeclen,
      v2hello    : TRUE 
    );

   send(socket:soc, data:chello);
   data = recv_ssl(socket:soc);
   if ( isnull(data) ) return -2;

   rec = ssl_find(
          blob:data,
          "content_type", SSL2_CONTENT_TYPE_SERVER_HELLO
   );
   if(! isnull(rec))
   {
     if(! isnull(rec['version']))
      return rec['version'];  
     else 
      return -3;  
   }
   else
    return -4;
  }
}

function is_ssl_banner()
{
 local_var banner;

 banner = _FCT_ANON_ARGS[0];

 if ( strlen(banner) < 5 ) return FALSE;

 if (  (substr(banner, 0, 2 ) == raw_string(0x15, 0x03, 0x01)) ||
       (substr(banner, 0, 4 ) == raw_string(0x15, 0x03, 0x00, 0x00, 0x02)) ||
       (substr(banner, 0, 4 ) == raw_string(0x80, 0x03, 0x00, 0x00, 0x01)) ||
      "error:1407609C:SSL routines:" >< banner )
	return TRUE;
 else
	return FALSE;
}

function three_digits(port, banner)
{
 if ( banner && banner =~ "^[0-9][0-9][0-9]($|-| )" )
  {
   set_kb_item(name:"Services/three_digits", value:port);
   return 1;
  }
}

function report_finding(port, proto, name, transport)
{
 local_var data;
 if ( isnull(name) ) name = 'A ' + proto + ' server';
 register_service(port:port, proto:proto);

 # nb: don't save www banners from an HTTP 1.0 request as they may
 #     cause problems for scans of name-based virtual hosts.
 if ( '\0' >!< g_banners[port] && proto != "www")
   replace_kb_item(name:proto + "/banner/" + port, value:g_banners[port]);

 data = name + ' is running on this port';
 if ( transport == ENCAPS_SSLv2 ) data +=' through SSLv2.';
 else if ( transport == ENCAPS_SSLv3 ) data +=' through SSLv3.';
 else if ( transport == ENCAPS_SSLv23 ) data +=' through SSLv23.';
 else if ( transport == ENCAPS_TLSv1 ) data +=' through TLSv1.';
 else if ( transport == COMPAT_ENCAPS_TLSv11 ) data +=' through TLSv1.1.';
 else if ( transport == COMPAT_ENCAPS_TLSv12 ) data +=' through TLSv1.2.';
 if (data[strlen(data)-1] != '.') data += '.';

 security_note(port:port, extra:data);
 return NULL;
}

function may_be_time()
{
 local_var now;
 local_var rt70;
 local_var diff_1970_1900;
 local_var max_shift;

 diff_1970_1900 = 2208988800;
 max_shift = 3*365*86400;

 set_byte_order(BYTE_ORDER_BIG_ENDIAN);
 rt70 = getdword(blob:_FCT_ANON_ARGS[0], pos:0) - diff_1970_1900;

 now = unixtime() - rt70;
 if ( now < 0 ) now = 0 - now;
 if ( now < max_shift ) return TRUE;
 else return FALSE;
}

function register_unknown(port, banner)
{
 if (strlen(banner) && banner =~ "^[0-9][0-9][0-9]($|-| )" ) return 0; # 3 digits

 set_kb_item(name:"Services/unknown", value:port);
 if ( strlen(banner) ) replace_kb_item(name:"unknown/banner/" + port, value:banner);
 return 0;
}

function register_silent()
{
 local_var port;
 port = _FCT_ANON_ARGS[0];
 set_kb_item(name:"Services/Silent/" + port , value:TRUE);
 set_kb_item(name:"Services/Silent", value:port);
 return 0;
}

#
# Signature based recognition
#
function recognize_banner(banner, port, transport)
{
 local_var low;
 local_var is_http;
 local_var info, ver;

 is_http = 0;

 if ( strlen(banner) == 0 )
	 return register_unknown(port:port, banner:banner);

 low = tolower(banner);

 if ( is_ssl_banner(banner) &&
     should_try_ssl(port) == FALSE &&
     transport == ENCAPS_IP )
 {
    g_ssl_ports_to_try[g_ssl_ports_to_try_idx++] = port;
    return;
 }

 if ( low =~ "^http/[0-9]\." || "<title>Not supported</title>" >< low || low =~ "^<html>" )
	{
	 # HTTP server
	 # MA 2008-07-16: we used to skip port 5000 because of vtun
	 if ( ! ( low =~ "^http/1\.0 403 forbidden" && "server: adsubtract" >< low ) &&
              ! ( "server: flashcom/" >< low )  &&
	      ! ( "server: heimdal/"  >< low ) &&
	      ! ( low =~ "^cimerror: ") )
			{
			is_http = 1;
			report_finding(port:port, proto:"www", name:"A web server", transport:transport);
			}
	}

 # NB: this must appear before telnet recognition else it will be
 #     flagged as that.
 if (
  strlen(banner) > 2 &&
  ord(banner[0]) == 255 && ord(banner[1]) >= 251 && ord(banner[1]) <= 254 &&
  "Welcome To jdkchat" >< banner &&
  "Commands available:" >< banner
 ) return report_finding(port:port, proto:"jdkchat", name:"A Telnet Chat Server from J.D. Koftinoff Software", transport:transport);

 # NB: this must also appear before Telnet.
 else if ( "Eggdrop" >< banner || "Eggheads" >< banner )
	return report_finding(port:port, proto:"eggdrop", name:"An eggdrop IRC bot control server", transport:transport);

 else if ( strlen(banner) > 2 &&
     ord(banner[0]) == 255 && ord(banner[1]) >= 251 && ord(banner[1]) <= 254 )
	return report_finding(port:port, proto:"telnet", transport:transport);

 else if ( "ccproxy telnet service ready" >< low)
	 	 return report_finding(port:port, proto:"ccproxy-telnet", name:"A CCProxy Telnet proxy", transport:transport);

 else if ( strlen(banner) >= 4 &&
     	substr(banner, 0, 3) == '\00\01\01\00')
	return report_finding(port:port, proto:"gnome14",name:"Gnome 1.4", transport:transport);


 else if ( "http/1.0 403 forbidden" >< low && "server: adsubtract" >< low )
	{
	return report_finding(port:port, proto:"AdSubtract",name:"A locked AdSubtract server", transport:transport);
	}

 else if ( "server: flashcom/" >< low )
	{
	return report_finding(port:port, proto:"rtmp",name:"Flash Media Server", transport:transport);
	}

 else if ( low =~ "^\$lock" )
	return report_finding(port:port, proto:"DirectConnectHub", name:"A Direct Connect Hub", transport:transport);

 else if ( strlen(low) > 34 && "iss ecnra built-in provider" >< substr(low, 34, strlen(low) - 1 ) )
	return report_finding(port:port, proto:"issrealsecure", name:"ISS RealSecure", transport:transport);

 else if ( strlen(banner) == 4 && banner == 'Q\00\00\00\00' )
	return report_finding(port:port, proto:"cpfw1", name:"Check Point FW1 SecuRemote or FW1 FWModule", transport:transport);
 else if ( low =~ "^ssl-tunnel/[0-9.]+ prot/[0-9.]+" )
	return report_finding(port:port, proto:"ssltunnel", name:"SSLTunnel (a VPN solution)", transport:transport);

 else if ( "adsgone blocked html ad" >< low )
	return report_finding(port:port, proto:"adsgone", name:"An AdsGone server", transport:transport);

 else if ( low =~ "icy 200 ok" )
	return report_finding(port:port, proto:"shoutcast",  transport:transport);

 else if ( low =~ "^200.*running eudora internet mail server" ||
	   "+ok applepasswordserver" >< low   ||
	   low =~ "^220.*poppassd" ||
	   low =~ "^200.*poppassd" ||
	   low =~ "^poppassd hello" )
	{
	 return report_finding(port:port, proto:"pop3pw", transport:transport);
	}
 else if ( banner =~ "^220" && " SNPP" >< banner )
	{
	 return report_finding(port:port, proto:"snpp", name:"An SNPP server", transport:transport);
	}

 else if ( getdword(blob:banner, pos:0) == (strlen(banner) - 4)&&
	   "krbtgt" >< banner )
	{
	 return report_finding(port:port, proto:"krbtgt", name:"A Kerberos ticket server", transport:transport);
	}

 else if ( "ccproxy" >< low && "smtp service ready" >< low)
	 	 return report_finding(port:port, proto:"ccproxy-smtp", name:"A CCProxy SMTP proxy", transport:transport);

 else if ( ("smtp" >< low ||
           "simple mail transfer" >< low ||
	   "mail server" >< low ||
	   "messaging" >< low ||
	   "connection rate limit exceeded" >< low ||
	   "weasel" >< low) && low =~ "^(220|421)" )
	 	 return report_finding(port:port, proto:"smtp", name:"An SMTP server", transport:transport);

# FTV-40905-469: False detection of an FTP server
# "220 ***************" >< banner
 else if (low =~ "^220 esafe(@|alert)" ||
	  low =~ "^220.*groupwise internet agent" )
	 	 return report_finding(port:port, proto:"smtp", name:"An SMTP server", transport:transport);

 else if ( ord(low[0]) != 0 && "host '" >< low && "mysql" >< low )
	 	 return report_finding(port:port, proto:"mysql", name:"A MySQL server", transport:transport);
 else if ( ord(low[0]) != 0 && "host '" >< low && "mariadb" >< low )
	 	 return report_finding(port:port, proto:"mysql", name:"A MariaDB server", transport:transport);
 else if ( ord(low[0]) != 0 && "can't create a new thread (errno" >< low && "if you are not out of available memory, you can consult" >< low )
	 	 return report_finding(port:port, proto:"mysql-broken", name:"A MySQL server which is out of resources", transport:transport);

 else if ( low =~ "^efatal" ||
	   low =~ "^einvalid packet length" )
	 	 return report_finding(port:port, proto:"postgresql", name:"A PostgreSQL server", transport:transport);

 else if ( "cvsup server ready" >< low )
	 	 return report_finding(port:port, proto:"cvsup", name:"A CVSup server", transport:transport);


 else if ( low =~ "cvs \[p?server aborted\]:" )
	 	 return report_finding(port:port, proto:"cvspserver", name:"A CVS pserver", transport:transport);


 else if ( low =~ "^cvslock" )
	 	 return report_finding(port:port, proto:"cvslock", name:"A CVSLock server", transport:transport);

 else if ( low =~ "@rsyncd" )
	 	 return report_finding(port:port, proto:"rsyncd", name:"An rsync server", transport:transport);

 else if ( strlen(banner) == 4 && may_be_time(banner) )
	 	 return report_finding(port:port, proto:"time", name:"A time server", transport:transport);

 else if ( ("rmserver" >< low || "realserver" >< low) && "server: apache" >!< low )
	 	 return report_finding(port:port, proto:"realserver", name:"A RealMedia server", transport:transport);

 else if ( "ccproxy ftp service" >< low )
	 	 return report_finding(port:port, proto:"ccproxy-ftp", name:"A CCProxy FTP proxy", transport:transport);

 else if ( ("ftp" >< low ||
	   "winsock" >< low ||
	   "axis network camera" >< low ||
	   "netpresenz" >< low ||
	   "serv-u" >< low ||
	   "service ready for new user" >< low ) && low =~ "^2[23]0" )
	 	 return report_finding(port:port, proto:"ftp", name:"An FTP server", transport:transport);
 else if ( low =~ "^220-"  && port != 25 && port  != 63  && port != 2628  )
	 	 return report_finding(port:port, proto:"ftp", name:"An FTP server", transport:transport);

 else if ( low =~ "^220" && "whois+" >< low )
	 	 return report_finding(port:port, proto:"whois++", name:"A whois++ server", transport:transport);
 else if ( "520 command could not be executed" >< low )
	 	 return report_finding(port:port, proto:"mon", name:"A mon server", transport:transport);

 else if ( egrep(pattern:"^SSH-[0-9.]+-", string:banner) )
	 	 return report_finding(port:port, proto:"ssh", name:"An SSH server", transport:transport);

 else if ( egrep(pattern:"^relaylock: ", string:banner) )
	 	 return report_finding(port:port, proto:"plesk-relay-lock", name:"An broken relay-lock server", transport:transport);

 else if ( "ok welcome to the nails statistics service" >< low)
                 return report_finding(port:port, proto:"nailsd", name:"NAILS Statistics Service from McAfee LinuxShield", transport:transport);

 else if ( "ccproxy" >< low && "pop3 service ready" >< low)
	 	 return report_finding(port:port, proto:"ccproxy-pop3", name:"A CCProxy POP3 proxy", transport:transport);

 else if ( low =~ "^\+ok" ||
	  ( low[0] == '+' && "pop" >< low ) )
		{
		 if ( port == 109 )
	 	  return report_finding(port:port, proto:"pop2", name:"A POP2 server", transport:transport);
	 	else
	 	  return report_finding(port:port, proto:"pop3", name:"A POP3 server", transport:transport);
		}
 else if ( low =~ "^\+ok *hello there" )
	 	  return report_finding(port:port, proto:"pop3", name:"A POP3 server", transport:transport);
 else if ( low =~ "^\-err this server is currently" )
	 	  return report_finding(port:port, proto:"broken-pop3", name:"A POP3 server under maintenance", transport:transport);

 else if ( ("imap4" >< low && low =~ "^\* ?ok") ||
	   low =~ "^\*ok iplanet messaging multiplexor" ||
	   low =~ "^\*ok communigate pro imap server" ||
	   low =~ "^\* ok courier-imap" ||
	   low =~ "^\* ok dbmail imap" ||
	   (low =~ "^\* ok server ready" && "unauthorized access prohibited." >< low) ||
           low =~ "^\* ok imaprev1" )
		return report_finding(port:port, proto:"imap", name:"An IMAP server", transport:transport);

 else if ( low =~ "^giop" )
		return report_finding(port:port, proto:"giop", name:"A GIOP-enabled service", transport:transport);

 else if ( "microsoft routing server" >< low )
		return report_finding(port:port, proto:"exchg-routing", name:"A Microsoft Exchange routing server", transport:transport);

 else if ( "gap service ready" >< low )
		return report_finding(port:port, proto:"iPlanetENS", name:"iPlanet ENS (Event Notification Server)", transport:transport);

 else if ("-service not available" >< low )
		return report_finding(port:port, proto:"tcpmux", transport:transport);
 else if ( strlen(banner) > 2 &&
	   substr(banner,0,4) == '\x7f\x7fICA' )
		return report_finding(port:port, proto:"citrix", name:"A Citrix server", transport:transport);
 else if (  "496365500100010003000e000000" >< hexstr(banner) )
		return report_finding(port:port, proto:"hp-remote-graphics", name:"An HP Remote Graphics server", transport:transport);
 else if ( banner =~ "^[0-9][0-9][0-9][ -]" &&
	   (" INN " >< banner ||
           " Leafnode " >< banner ||
	   "  nntp daemon" >< low ||
	   " nnrp service ready" >< low ||
	   " nntp server ready" >< low ||
	   "posting ok"  >< low ||
	   "posting allowed" >< low ||
	   "502 no permission" >< low ||
	   low =~ "^502.*diablo"  ) )
		return report_finding(port:port, proto:"nntp", name:"An NNTP server", transport:transport);

 else if (  "networking/linuxconf" >< low ||
	    "networking/misc/linuxconf" >< low ||
	    "server: linuxconf" >< low )
		return report_finding(port:port, proto:"linuxconf", name:"LinuxConf", transport:transport);

 else if ( banner =~ "^gnudoit:" )
		return report_finding(port:port, proto:"gnuserv", name:"A GNUserv server", transport:transport);

 else if ( strlen(banner) > 5 &&
	   ( banner[0] == '0' && 'error.host\t1' >< low ) ||
	   ( banner[0] == '3' && 'That item is not current available' >< banner ) ||
	   ( banner[0] == '3' && "--6 Bad Request" >< banner ) )
		return report_finding(port:port, proto:"gopher", name:"A Gopher server", transport:transport);

 else if ('www-authenticate: basic realm="swat"' >< low )
		return report_finding(port:port, proto:"swat", name:"A SWAT server", transport:transport);

 else if ("vqserver" >< low && "www-authenticate: basic realm=/" >< low )
		return report_finding(port:port, proto:"vqServer-admin", transport:transport);
 else if ( "1invalidrequest" >< low )
		return report_finding(port:port, proto:"mldonkey", name:"MLDonkey, a peer-to-peer client,", transport:transport);
 else if ( "get: command not found" >< low )
		return report_finding(port:port, proto:"wild_shell", name:"A shell server (possible backdoor)", transport:transport);

 else if ( "Microsoft Windows" >< banner &&
	   "C:\" >< banner &&
	   "(C) Copyright 1985-" >< banner &&
	   "Microsoft Corp." >< banner )
		return report_finding(port:port, proto:"wild_shell", name:"A shell server (possible backdoor)", transport:transport);

 else if ( low == "root@metasploitable:/# ")
		return report_finding(port:port, proto:"wild_shell", name:"A shell server (Metasploitable)", transport:transport);

 else if ( "Tiny command server. This is a remote command server, not a telnet server." >< banner )
		return report_finding(port:port, proto:"wild_shell", name:"A shell server (rcmd.bat) from IpTools", transport:transport);

 else if ( "netbus" >< banner )
		return report_finding(port:port, proto:"netbus", name:"NetBus", transport:transport);


 else if ( "0 , 0 : error : unknown-error" >< low ||
	   "0, 0: error: unknown-error" >< low ||
	   "get : error : unknown-error" >< low ||
	   "0 , 0 : error : invalid-port" >< low ||
           egrep(string: low, pattern:"^[0-9]+ *, *[0-9]+ *: * userid *: *[^: ]* *:") )
		return report_finding(port:port, proto:"auth", name:"An identd server", transport:transport);

 else if ( low =~ "^http/1\." && egrep(pattern:"^dav:.*calendar-(access|schedule|proxy)", string:low ) )
	{
		return report_finding(port:port, proto:"caldav", name:"A CalDAV server", transport:transport);
	}
 else if ( low =~ "^http/1\." && egrep(pattern:"^dav:.*calendarserver-principal-property-search", string:low ) )
	{
		return report_finding(port:port, proto:"caldav-property", name:"A CalDAV property server", transport:transport);
	}
 else if (
	   (egrep(pattern:"^http/1\..*proxy", string:low) && !egrep(pattern:"^cache-control:.*proxy-revalidate", string:low)) ||
	   (low =~ "^http/1\." && egrep(pattern:"^via:", string:low) ) ||
	   (low =~ "^http/1\." && egrep(pattern:"^proxy-connection: ", string:low) ) ||
	   (low =~ "^http/1\." && egrep(pattern:"^anon-proxy: ", string:low) ) ||
	   #(low =~ "^http/1\." && "cache" >< low && "bad request" >< low ) ||
           # TudouVA (see BID 47508)
           ("HTTP/1.0 404 Not Found" >< banner && "Server: mmsserver" >< banner && "Allow: GET, HEAD, DELETE" >< banner && "error" >< banner)
         )
	 {
           return report_finding(port:port, proto:"http_proxy", name:"An HTTP proxy", transport:transport);
         }

 else if ( low =~ "^http/1\." && "gnutella " >< low )
		return report_finding(port:port, proto:"gnutella", name:"A Gnutella servent", transport:transport);

 else if ( banner =~ "^RFB 00" )
		return report_finding(port:port, proto:"vnc", transport:transport);

 else if ( low =~ "^ncacn_http/1\." )
	{
	 	if ( port == 593 ) return report_finding(port:port, proto:"http-rpc-epmap", name:"An http-rpc-epmap", transport:transport);
		else return report_finding(port:port, proto:"ncacn_http", name:"An ncacn_http server", transport:transport);
	}

 else if ( 'GET / HTTP/1.0\r\n\r\n'  == banner )
		return report_finding(port:port, proto:"echo", name:"An echo server", transport:transport);

 else if ( '!"#$%&\'()*+,-./' >< banner &&
	   'ABCDEFGHIJ' >< banner &&
	   'abcdefg' >< banner &&
	   '0123456789' >< banner ) return report_finding(port:port, proto:"chargen", transport:transport);


 else if ( "vtun server" >< low )
		return report_finding(port:port, proto:"vtun", name:"A VTUN (Virtual Tunnel) server", transport:transport);

 else if ( low == "login: password: "   ||
	   ( banner =~ "^login: " && port == 540 ))
		return report_finding(port:port, proto:"uucp", transport:transport);

 else if ( low =~ "^bad request" ||
	   "invalid protocol request (71): gget / http/1.0" >< low ||
	   low =~ "^lpd:" ||
	   "^lpsched" >< low ||
	   "malformed from address" >< low ||
	   "no connect permissions" >< low )
		return report_finding(port:port, proto:"lpd", name:"An LPD (Line Printer Daemon) server", transport:transport);


 else if ( "%%lyskom unsupported protocol" >< low )
		return report_finding(port:port, proto:"lyskom", transport:transport);

 else if ( "598:get:command not recognized"  >< low )
		return report_finding(port:port, proto:"ph", transport:transport);

 else if ("BitTorrent prot" >< banner )
		return report_finding(port:port, proto:"BitTorrent", name:"BitTorrent", transport:transport);

 else if ( strlen(banner) >= 3 && substr(banner, 0, 2) == 'A\x01\x02' )
		return report_finding(port:port, proto:"smux", name:"An SNMP Multiplexer (smux)", transport:transport);

 else if ( low =~ "^0 succeeded" )
		return report_finding(port:port, proto:"LISa", name:"A LISa daemon", transport:transport);


 else if ( "welcome!psybnc@" >< low ||
	   "notice * :psybnc" >< low )
		return report_finding(port:port, proto:"psybnc", name:"PsyBNC (IRC proxy)", transport:transport);

 else if ( banner =~ "^\* ACAP " )
		return report_finding(port:port, proto:"acap", name:"An ACAP server", transport:transport);

 else if ( low =~ "Sorry, you ([0-9.]*) are not among the allowed hosts" )
		return report_finding(port:port, proto:"nagiosd", name:"Nagios", transport:transport);

 else if ( banner == '[TS]\nerror\n' || banner == '[TS]\r\nerror\r\n' )
		return report_finding(port:port, proto:"teamspeak-tcpquery", transport:transport);
 else if ( 'TS3 Client' >< banner && 'TeamSpeak 3 ClientQuery interface' >< banner )
		return report_finding(port:port, proto:"teamspeak3-tcpquery", transport:transport);
 else if ( banner =~ "^Language received from client: GET / HTTP/1\.0" )
		return report_finding(port:port, proto:"websm", name:"A WEBSM server", transport:transport);

 else if ( banner == "CNFGAPI" )
		return report_finding(port:port, proto:"ofa_express", name:"An OFA/Express server", transport:transport);

 else if ( banner =~ "^SuSE Meta pppd" )
		return report_finding(port:port, proto:"smppd", name:"A SuSE Meta pppd server", transport:transport);

 else if ( banner =~  "^ERR UNKNOWN-COMMAND" )
		return report_finding(port:port, proto:"upsmon", name:"A upsd/upsmon server", transport:transport);

 else if ( banner =~ "^connected\..*, ver: Legends" )
		return report_finding(port:port, proto:"sub7", name:"A Sub7 trojan", transport:transport);

 else if ( banner =~ "^SPAMD/[0-9.]*" )
		return report_finding(port:port, proto:"spamd", name:"SpamAssassin (spamd)", transport:transport);

 else if ( banner =~ "^220" && " dictd " >< low )
		return report_finding(port:port, proto:"dictd", name:"dictd, a dictionary database server,", transport:transport);

 else if ( banner =~ "^220 " && "VMware Authentication Daemon" >< banner )
		return report_finding(port:port, proto:"vmware_auth", name:"A VMware authentication daemon", transport:transport);


 else if ( low =~ "^220.* interscan version" )
		return report_finding(port:port, proto:"interscan_viruswall", name:"An InterScan VirusWall", transport:transport);

 else if ( strlen(banner) > 1 && banner[0] == '~' && banner[strlen(banner) - 1] == '~' && !isnull(strstr(banner, '}')) )
		return report_finding(port:port, proto:"pppd", name:"A PPP daemon", transport:transport);

 else if ( banner =~ "Hello, this is ([Zz]ebra|[Qq]uagga)" )
		return report_finding(port:port, proto:"zebra", name:"A zebra daemon", transport:transport);

 else if ( "NOTICE AUTH :" >< banner || "NOTICE Auth :" >< banner )
 {
   return report_finding(port:port, proto:"irc", name:"An IRC server");
 }

 else if ( "ircxpro " >< low )
		return report_finding(port:port, proto:"ircxpro_admin", name:"An IRCXPro administrative server", transport:transport);

 else if ( low =~ "^.*version report"  )
		return report_finding(port:port, proto:"gnocatan", name:"A Gnocatan game server", transport:transport);

 else if ( banner =~ "^RTSP/1\.0.*QTSS/"  )
		return report_finding(port:port, proto:"quicktime-streaming-server", name:"A Quicktime streaming server", transport:transport);
 else if ( banner =~ "^RTSP/1.0 400 " )
		return report_finding(port:port, proto:"rtsp", name:"A streaming server is running on this port", transport:transport);

 else if ( strlen(banner) > 2 && ord(banner[0]) == 0x30 && ord(banner[1]) == 0x11 && ord(banner[2]) == 0 )
		return report_finding(port:port, proto:"dameware", transport:transport);

 else if ( "stonegate firewall" >< low )
		return report_finding(port:port, proto:"SG_ClientAuth", name:"A StoneGate authentication server", transport:transport);

 else if ( low =~ "^pbmasterd" )
 {
		info = "A PowerBroker master server";

		ver = eregmatch(string:low, pattern:'^pbmasterd([0-9.-]+)@');
		if (ver)
		{
		  info += ' (version ' + ver[1] + ')';
		  set_kb_item(name:'pbmasterd/' + port + '/version', value:ver[1]);
		}

		return report_finding(port:port, proto:"power-broker-master", name:info, transport:transport);
 }

 else if ( low =~ "^pblocald" )
 {
		info = "A PowerBroker locald server";

		ver = eregmatch(string:low, pattern:'^pblocald([0-9.-]+)@');
		if (ver)
		{
		  info += ' (version ' + ver[1] + ')';
		  set_kb_item(name:'pblocald/' + port + '/version', value:ver[1]);
		}

		return report_finding(port:port, proto:"power-broker-locald", name:info, transport:transport);
 }

 else if ( low =~ "^pblogd" )
 {
		info = "A PowerBroker logd server";

		ver = eregmatch(string:low, pattern:'^pblogd([0-9.-]+)@');
		if (ver)
		{
		  info += ' (version ' + ver[1] + ')';
		  set_kb_item(name:'pblogd/' + port + '/version', value:ver[1]);
		}

		return report_finding(port:port, proto:"power-broker-logd", name:info, transport:transport);
 }

 else if ( low =~ "^<stream:error>invalid xml</stream:error>" )
		return report_finding(port:port, proto:"jabber", name:"jabber", transport:transport);

 else if ( low =~ "^/c -2 get ctgetoptions" )
		return report_finding(port:port, proto:"avotus_mm", name:"An avotus 'mm' server", transport:transport);

 else if ( low =~ "^error:wrong password" )
		return report_finding(port:port, proto:"pNSClient", name:"pNSClient.exe, a Nagios plugin,", transport:transport);

 else if ( banner =~ "^1000      2" )
		return report_finding(port:port, proto:"VeritasNetBackup", name:"Veritas NetBackup", transport:transport);

 else if ("the file name you specified is invalid" >< low &&
	  "listserv" >< low )
		return report_finding(port:port, proto:"listserv", name:"A LISTSERV daemon", transport:transport);

 else if ( low =~ "^control password:" )
		return report_finding(port:port, proto:"FsSniffer", name:"FsSniffer, a password-stealing backdoor,", transport:transport);

 else if ( banner == "Gh0st" )
		return report_finding(port:port, proto:"ghost-rat", name:"Gh0st, a Remote Admin Tool often used as a backdoor,", transport:transport);

 else if ( low =~ "^remotenc control password:")
		return report_finding(port:port, proto:"RemoteNC", name:"RemoteNC, a backdoor trojan,", transport:transport);

 else if ( "error while loading shared libraries :" >< low )
		return report_finding(port:port, proto:"broken-inetd", name:"A broken inetd service (which can't load the shared libraries it depends on)", transport:transport);

 else if ( "A E O N I A N   D R E A M S" >< banner &&
            "R E A W A K E N E D" >< banner )
		return report_finding(port:port, proto:"aeonian-dreams", name:"A 'Aeonian Dreams' game server", transport:transport);


 else if ( "finger: GET: no such user" >< banner  ||
	   "finger: /: no such user" >< banner ||
	   "finger: HTTP/1.0: no such user" >< banner ||
	   "Login       Name               TTY         Idle    When    Where" >< banner ||
	   "Line     User" >< banner ||
	   "Login name: GET" >< banner )
		return report_finding(port:port, proto:"finger", name:"A finger daemon", transport:transport);

 else if ( strlen(banner) >= 4 && ord(banner[0]) == 5 && ord(banner[1]) <= 8 && ord(banner[2]) == 0 && ord(banner[3]) <= 4 && ord(banner[1]) == strlen(banner) - 2)
		return report_finding(port:port, proto:"socks5",name:"A SOCKS5 proxy", transport:transport);
 else if ( strlen(banner) >= 4 && ord(banner[0]) == 0 && ord(banner[1]) >= 90 && ord(banner[1]) <= 93 )
		return report_finding(port:port, proto:"socks4",name:"A SOCKS4 proxy", transport:transport);
 else if ( egrep(pattern:"^server: heimdal/[0-9.]+", string:low) )
 {
  low = ereg_replace(pattern:"^server: heimdal/([0-9.]+).*", string:egrep(pattern:"^server: heimdal/[0-9.]+", string:low), replace:"\1");
  return report_finding(port:port, proto:"krbtgt", name:"A kerberos ticketing server (Heimdal v" + chomp(low) + ")", transport:transport);
 }
 # nb: this looks like a broken web server; eg, it responds to GET requests with:
 #     HTTP/1.1 501 Not Implemented
 #     CIMError: Only POST and M-POST are implemented
 else if ( egrep(pattern:"^cimerror: ", string:low) )
 {
  return report_finding(port:port, proto:"cim_listener", name:"A CIM Listener", transport:transport);
 }
 else if ( banner =~ "^<<<check_mk>>>" )
 {
  return report_finding(port:port, proto:"check_mk", name:"A Check_MK agent", transport:transport);
 }
 else if ( banner =~ "Groovy Shell" &&
           'Type \'go\' to execute statements' >< banner)
 {
  return report_finding(port:port, proto:"groovy_shell", name:"Groovy Shell", transport:transport);
 }
 else if (banner =~ "^Android Console: type 'help' for a list of commands\r\nOK\r\n")
 {
   return report_finding(port:port, proto:"android_emulator_telnet", name:"An Android Emulator Telnet service", transport:transport);
 }
 else if (banner =~ '^\\(error "-3: \\([^)]+\\): Command not supported"\\)')
{
  return report_finding(port:port, proto:"cogent_datahub_mirror", name:"Cogent DataHub Tunnel/Mirror service", transport:transport);
}
 else if (
   "ViPER Monitor Transport Protocol" >< banner &&
   "ViPERManager" >< banner
 )
 {
   # nb: may be associated with Mitel ViPER virtual cards for giving IP addresses to legacy devices.
   return report_finding(port:port, proto:"vmtp", name:"A ViPER Monitor Transport Protocol (VMTP) service", transport:transport);
 }
 else if (
   banner == '0 {}\r\n' ||
   banner == '0 {}\n'
 )
 {
   return report_finding(port:port, proto:"3par_mgmt", name:"HP 3PAR Management Service", transport:transport);
 }
 else if (
   'FSAE server' >< banner &&
   'FSAE_SERVER_' >< banner &&
   getdword(blob:banner, pos:0) == strlen(banner))
 {
   report_finding(port:port, proto:"fsae_server", name:"Fortinet Server Authentication Agent", transport:transport);
 }

 else if ( is_http != 1 )
	 return register_unknown(port:port, banner:banner);




 return NULL;
}

#------------------#
# Banner Grabbing  #
#------------------#

function ssl_ports_init()
{
 local_var item;

 g_ssl_ports_H = make_array();

 foreach item ( g_ssl_ports ) g_ssl_ports_H[item] = TRUE;
}


#
# Functions definitions
#

function should_try_ssl()
{
 local_var port;
 local_var s, e;

 if ( SSL_PORT_TO_CONNECT == SSL_CONNECT_ALL ) return TRUE;
 else if ( SSL_PORT_TO_CONNECT == SSL_CONNECT_NONE ) return FALSE;

 port = _FCT_ANON_ARGS[0];

 if ( g_ssl_ports_H[port] == TRUE ) return TRUE;

 return FALSE;
}

function port_push()
{
 if ( _FCT_ANON_ARGS[0] == 139 || _FCT_ANON_ARGS[0] == 445 || _FCT_ANON_ARGS[0] == 3389 ) return; # Do not scan port 139, 445 or 3389
# display("Push ", _FCT_ANON_ARGS[0], "\n");
 g_port_pool[g_port_pool_max++] = _FCT_ANON_ARGS[0];
}

function port_pop()
{
 if ( g_port_pool_idx >= g_port_pool_max ) return NULL;
 else return g_port_pool[g_port_pool_idx++];
}

function port_new()
{
 local_var port;
 local_var banner;

 port = port_pop();
 if ( port == NULL ) return FALSE;

 #
 # Check whether nessus_tcp_scanner found the banner already
 #
 banner = get_kb_item("BannerHex/" + port);
 if ( isnull(banner) ) banner = get_kb_item( "Banner/" + port );
 else banner = hex2raw(s:banner);


 if ( should_try_ssl(port) == FALSE )
   g_transport_state[port] = E_STATE_IP;
 else
   g_transport_state[port] = E_STATE_SSL_START;

 g_sock_state[port] = S_STATE_CONNECTING;
 g_methods[port] = "spontaneous";

 if ( ! isnull(banner) )
 {
   if ( is_ssl_banner(banner) )
	{
	  # This looks like SSL - let's force a negotiation here
   	  g_transport_state[port] = E_STATE_SSL_START;
	}
   else
	{
   	 g_transport_state[port] = E_STATE_IP;
   	 g_sock_state[port] = S_STATE_DONE;
   	 g_banners[port] = banner;
	 replace_kb_item(name:"Transports/TCP/" + port, value:ENCAPS_IP);
   	 return port_new();
	}
 }

 g_timestamps[port] = unixtime();
 if ( g_sock[port] > 0 ) close(g_sock[port]);
 g_sock[port] = open_sock_tcp(port, transport:state_to_transport[g_transport_state[port]], nonblocking:TRUE);
 return TRUE;
}

function port_done()
{
 local_var port;

 port = _FCT_ANON_ARGS[0];

 g_sock_state[port] = S_STATE_DONE;
 close(g_sock[port]);
 g_sock[port] = NULL;

 port_new();
}

function mark_wrapped_svc()
{
 local_var port;

 port = _FCT_ANON_ARGS[0];
 if ( port == 514 ) return;
 security_note(port:port, extra:'The service closed the connection without sending any data.\nIt might be protected by some sort of TCP wrapper.');
 set_kb_item(name:"Services/wrapped", value:port);
}

function port_connect_error()
{
 local_var port;

 port = _FCT_ANON_ARGS[0];
 if ( g_transport_state[port] < E_STATE_IP )
	{
	 g_transport_state[port] ++;
 	 g_sock_state[port] = S_STATE_CONNECTING;
 	 g_timestamps[port] = unixtime();
   	 if ( g_sock[port] > 0 ) close(g_sock[port]);
 	 g_sock[port] = open_sock_tcp(port, transport:state_to_transport[g_transport_state[port]], nonblocking:TRUE);
	}
 else
	port_done(port);
}

#
# e = error from socket_get_error()
#
function port_process(port, e)
{
 local_var note, ver;
 if ( e < 0 )
 {
  if ( g_transport_state[port] < E_STATE_IP )
	{
	 g_transport_state[port] ++;
 	 g_sock_state[port] = S_STATE_CONNECTING;
 	 g_timestamps[port] = unixtime();
 	 if ( g_sock[port] > 0 ) close(g_sock[port]);
 	 g_sock[port] = open_sock_tcp(port, transport:state_to_transport[g_transport_state[port]], nonblocking:TRUE);
	}
  else port_done(port);
 }
 else
 {
  if ( (g_transport_state[port] == E_STATE_TLSv11 && !TLSv1_1_AVAILABLE) || 
       (g_transport_state[port] == E_STATE_TLSv12 && !TLSv1_2_AVAILABLE) || 
        g_transport_state[port] == E_STATE_TLS_HELLO || 
        g_transport_state[port] == E_STATE_SSL3_HELLO || 
        g_transport_state[port] == E_STATE_SSL2_HELLO)
  {
   ver = SSL_hello(port:port);
   if ( ver > 0 )
   {
    note = '';
    g_sock_state[port] = S_STATE_DONE;

    set_kb_item(name:"Transport/SSL", value:port);

    # Do *NOT* set Transport/TCP/<port> here as the engine does not support TLSv1.1+

    # These KBs are set by ssl_supported_versions.nasl, why set here?
    #if (  g_transport_state[port] == E_STATE_TLSv11 )
    #	set_kb_item(name:"SSL/Transport/" + port, value:COMPAT_ENCAPS_TLSv11);
    #else
    #	set_kb_item(name:"SSL/Transport/" + port, value:COMPAT_ENCAPS_TLSv12);

    if ( ver == TLS_11 ) note = 'A TLSv1.1';
    else if (ver == TLS_12 ) note = 'A TLSv1.2';
    else if (ver == TLS_10 ) note = 'A TLSv1';
    else if (ver == SSL_V3 ) note = 'A SSLv3';
    else if (ver == SSL_V2 ) note = 'A SSLv2';
    if ( strlen(note) > 0 )
    {
     note = note + ' server answered on this port.\n';
     security_note(port:port, extra:note);
    }
    port_done(port);
    return;
   }
   else
   {
    g_transport_state[port] ++;
    g_sock_state[port] = S_STATE_CONNECTING;
    g_timestamps[port] = unixtime();
    if ( g_sock[port] > 0 ) close(g_sock[port]);
    g_sock[port] = open_sock_tcp(port, transport:state_to_transport[g_transport_state[port]], nonblocking:TRUE);
    return;
   }
  }
  # We are connected
  replace_kb_item(name:"Transports/TCP/" + port, value:state_to_transport[g_transport_state[port]]);
  if( state_to_transport[g_transport_state[port]] != ENCAPS_IP )
	{
	set_kb_item(name:"Transport/SSL", value:port);
 	if ( state_to_transport[g_transport_state[port]] == ENCAPS_SSLv2 ) note ='An SSLv2';
 	else if ( state_to_transport[g_transport_state[port]] == ENCAPS_SSLv3 ) note ='An SSLv3';
 	else if ( state_to_transport[g_transport_state[port]] == ENCAPS_TLSv1 ) note ='A TLSv1';
 	else if ( state_to_transport[g_transport_state[port]] == COMPAT_ENCAPS_TLSv11 ) note ='A TLSv1.1';
 	else if ( state_to_transport[g_transport_state[port]] == COMPAT_ENCAPS_TLSv12 ) note ='A TLSv1.2';
	else note = NULL;
	if ( note )
	 {
	 note = note + ' server answered on this port.\n';
	 security_note(port:port, extra:note);
	 }
	}

  g_sock_state[port] = S_STATE_READING;
 }
}

function port_send_get()
{
  local_var port;

  port = _FCT_ANON_ARGS[0];

  send(socket:g_sock[port], data:'GET / HTTP/1.0\r\n\r\n');
  g_sock_state[port] = S_STATE_READING_W_GET;
  g_methods[port] = "get_http";
}

function select()
{
 local_var port;
 local_var now;
 local_var e;
 local_var num;

 num = 0;
 now = unixtime();

 foreach port ( keys(g_sock) )
 {
  if ( g_sock_state[port] == S_STATE_CONNECTING )
  {
    num ++;
    e =  socket_get_error(g_sock[port]);
    if ( e != 0 && e != EINPROGRESS )
	{
	 if ( e == ECONNREFUSED ) port_done(port);
	 else port_connect_error(port); # Some error occurred
	}

    e = socket_ready(g_sock[port]);
    if ( e > 0 ) port_process(port:port, e:e);
    else if ( e == 0 && (socket_get_error(g_sock[port]) != 0 &&
			 socket_get_error(g_sock[port]) != EINPROGRESS) ) port_connect_error(port);
    else if ( e < 0 || (now - g_timestamps[port] >= CONNECT_TIMEOUT) ) port_connect_error(port);
  }
  else if ( g_sock_state[port] == S_STATE_READING )
  {
   num ++;
   if ( socket_pending(g_sock[port]) )
	{
	 g_banners[port] = recv(socket:g_sock[port], length:65535);
	 #display(hexstr(g_banners[port]), "\n");
	 if ( isnull(g_banners[port]) && socket_get_error(g_sock[port]) == ECONNRESET )
			 mark_wrapped_svc(port);
	 else if ( isnull(g_banners[port]) )
	 		 register_unknown(port:port, banner:NULL);
	 port_done(port);
	}
   else if ( now - g_timestamps[port] >= SPONTANEOUS_TIMEOUT )
	 port_send_get(port);
  }
  else if ( g_sock_state[port] == S_STATE_READING_W_GET )
  {
   num ++;
   if ( socket_pending(g_sock[port]) )
	{
	 g_banners[port] = recv(socket:g_sock[port], length:65535);
	 #display(hexstr(g_banners[port]), "\n");
	 if ( g_banners[port] == NULL ) register_unknown(port:port, banner:NULL);
	 port_done(port);
	}
   else if ( now - g_timestamps[port] >= TIMEOUT)
	{
	 register_unknown(port:port, banner:NULL);
	 register_silent(port);
	 port_done(port);
	}
  }
 }

 return num;
}

#-----------#
# Main      #
#-----------#

function main()
{
 local_var list, item, i, port;
 local_var pref, rt, to2, k;

 rt = get_read_timeout();

 pref = int(get_preference("max_checks"));
 if (pref > 0)
 {
   MAX_SIMULT_CONNECTIONS = pref;
   if (islocalnet())
     MAX_SIMULT_CONNECTIONS *= 2;
   else
   {
     # Congestion information in KB is not reliable in 4.0.1 or earlier
     pref = int(get_preference("TCPScanner/NbPasses"));
     if (pref <= 0) pref = int(get_preference("SYNScanner/NbPasses"));
     if (pref > 0 && pref <= 2) pref *= 2;
   }
 }
 # Just in case..
 foreach k (make_list("max_simult_tcp_sessions", "global.max_simult_tcp_sessions", "host.max_simult_tcp_sessions"))
 {
   pref = int(get_preference(k));
   if (pref > 0 && MAX_SIMULT_CONNECTIONS > pref)
    MAX_SIMULT_CONNECTIONS = pref;
  }

 if ( MAX_SIMULT_CONNECTIONS > 32 ) MAX_SIMULT_CONNECTIONS = 32;
 set_kb_item(name: "FindService/MaxSimultCnx", value: MAX_SIMULT_CONNECTIONS);
 if (rt > 30)
   to2 = rt;
 else
 {
  to2 = 2 * rt;
  if (to2 > 30) to2 = 30;
 }

 CONNECT_TIMEOUT = to2;
 TIMEOUT = to2;

 pref = script_get_preference("Test SSL based services");
 if ( "All" >< pref ) SSL_PORT_TO_CONNECT = SSL_CONNECT_ALL;
 if ( "None" >< pref ) SSL_PORT_TO_CONNECT = SSL_CONNECT_NONE;
 if ( "Known SSL ports" >< pref ) SSL_PORT_TO_CONNECT = SSL_CONNECT_KNOWN;

 list = get_kb_list("Ports/tcp/*");
 if ( isnull(list) ) exit(0); # No open port

 list = make_list(keys(list));
 if ( max_index(list) > 1500 ) exit(1, "Too many open ports.");


 foreach item (list)
 {
   	if (service_is_unknown(port:int(item - "Ports/tcp/")) )
	  port_push(int(item - "Ports/tcp/"));
 }

 for ( i = 0 ; i < MAX_SIMULT_CONNECTIONS ; i ++ )
	if ( port_new() == FALSE ) break;

 while ( select() != 0 ) usleep(5000);

 foreach port ( keys(g_banners) )
 {
  if ( isnull(g_banners[port]) )
  {
	 register_unknown(port:port, banner:NULL);
	 continue;
  }
  #display(hexstr(g_banners[port]), "\n");
  set_kb_banner(port: port, type: g_methods[port], banner: g_banners[port]);
  three_digits(port:port, banner:g_banners[port]);
  recognize_banner(banner:g_banners[port], port:port, transport:state_to_transport[g_transport_state[port]]);
 }
}

#
# This function goes through every service which showed an SSL error when
# being connected to, and forces a SSL negotiation on these.
#
function try_non_std_ssl_ports()
{
 local_var i, port;

 #display("g_ssl_ports = ", g_ssl_ports_to_try_idx, "\n");
 if ( g_ssl_ports_to_try_idx == 0 ) return;

 #
 # Reset globals
 #
 globals_reset();

 #
 # Mark all ports to be SSL compatible
 #
 SSL_PORT_TO_CONNECT = SSL_CONNECT_ALL;

 for ( i = 0 ; i < g_ssl_ports_to_try_idx ; i ++ )
  port_push(g_ssl_ports_to_try[i]);

 for ( i = 0 ; i < MAX_SIMULT_CONNECTIONS ; i ++ )
	if ( port_new() == FALSE ) break;

 while ( select() != 0 ) usleep(5000);
 foreach port ( keys(g_banners) )
 {
  if ( isnull(g_banners[port]) ) continue;
  set_kb_banner(port: port, type: g_methods[port], banner: g_banners[port]);
  three_digits(port:port, banner:g_banners[port]);
  recognize_banner(banner:g_banners[port], port:port, transport:state_to_transport[g_transport_state[port]]);
 }
}

globals_init();
ssl_ports_init();
main();
try_non_std_ssl_ports();
