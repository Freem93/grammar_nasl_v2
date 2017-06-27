#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(19689);
 script_version("$Revision: 1.79 $");
 script_cvs_date("$Date: 2017/05/26 23:42:52 $");

 script_name(english:"Embedded Web Server Detection");
 script_summary(english:"This scripts detects whether the remote host is an embedded web server.");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is embedded.");
 script_set_attribute(attribute:"description", value:
"The remote web server cannot host user-supplied CGIs. CGI scanning
will be disabled on this server.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2017 Tenable Network Security, Inc.");

 script_family(english:"Web Servers");

 script_dependencies("cisco_ids_manager_detect.nasl", "ciscoworks_detect.nasl", "ilo_detect.nasl",
"clearswift_mimesweeper_smtp_detect.nasl", "imss_detect.nasl", "interspect_detect.nasl", "intrushield_console_detect.nasl", "ibm_rsa_www.nasl",
"veritas_cluster_mgmt_detect.nasl",	# Not an embedded web server per se
"iwss_detect.nasl", "linuxconf_detect.nasl", "securenet_provider_detect.nasl",
"tmcm_detect.nasl", "websense_detect.nasl", "xedus_detect.nasl", "xerox_document_centre_detect.nasl", "xerox_workcentre_detect.nasl", "compaq_wbem_detect.nasl", "drac_detect.nasl", "net_optics_director_web_detect.nbin");

 script_require_ports("Services/www", 80);
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_service(svc:"www", default:80, exit_on_fail:TRUE);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0, "The web server listening on port "+port+" has already been marked as 'embedded'.");

banner = get_http_banner(port:port, exit_on_fail:TRUE);
if (
  port == 901 ||
  egrep(string: banner, pattern:"^(DAAP-)?([Ss]erver|SERVER): *(ADTRAN, Inc\.|BarracudaHTTP|BOSSERV/|CUPS|MiniServ|AppleShareIP|Embedded HTTPD|Embedded HTTP Server.|httpd [0-9]|IP_SHARER|Ipswitch-IMail|KM-MFP-http/V|MACOS_Personal_Websharing|NetCache appliance|(ZyXEL-)?RomPager/|cisco-IOS|u-Server|eMule|Allegro-Software-RomPager|RomPager|Desktop On-Call|D-Link|4D_WebStar|IPC@CHIP|Citrix Web PN Server|SonicWALL|Micro-Web|gSOAP|CompaqHTTPServer/|BBC [0-9.]+; .*[cC]oda|ida-HTTPServer|HP Web Jetadmin|HP-Web-JetAdmin|Xerox_MicroServer|HP-ChaiServer|Squid/Alcatel|HTTP Server$|Virata-EmWeb|RealVNC|gSOAP|dncsatm|Tandberg Television Web server|UPSentry|Service admin/|Gordian Embedded|eHTTP|SMF|Allegro-Software-RomPager|3Com/|SQ-WEBCAM|WatchGuard Firewall|Acabit XML-RPC Server|EWS-NIC|3ware/|RAC_ONE_HTTP|GoAhead|BBC|CCM Desktop Agent|iTunes/|LANDesk Management Agent/|Rapid Logic/|RapidLogic/|NetPort Software|NetEVI/|micro_httpd| UPnP/1\.[01]|WindWeb/|IP-Phone Solution|DCReport/|ESWeb/|Axigen-Webadmin|Axigen-Webmail|OfficeScan Client|glass/.+-IronPort|KDG/[0-9]|EPSON-IPP/[0-9]|Sun-ILOM-Web-Server/1.0|Oracle-ILOM-Web-Server/1.0|Check Point SVN foundation|HASP LM/[0-9]|PSOSHTTP/[0-9]|Novell-Agent [0-9.]+ |DHost/[0-9.]+ HttpStk/[0-9.]+|SiteScope/[0-9]|PRTG/[0-9]|portex/1\.0|mt-daapd/|W3MFC/[0-9]|Agent-ListenServer-HttpSvr|DVS 304 Series/1.21|LVAHTTPD/ver[0-9]|Asterix/[0-9]|JC-HTTPD/|PRINT_SERVER WEB [0-9]|silex Web Admin|AKCP Embedded Web Server|Muratec Server Ver.[0-9]|EPSON-HTTP/|AnomicHTTPD|PanWeb Server/|Splunkd|ZenAgent|TSM_HTTP/|Motion-httpd/[0-9]\.|TembriaWebServer|TRMB/[0-9]|Vivotek Network Camera|Vivotek Video Server|R4 Embedded Server|WIBU-SYSTEMS HTTP Server|SNARE/[0-9.]+|Snare/[0-9.]+|Wing FTP Server/|IPWEBS/|GE Industrial Systems UR)")
) set_kb_item(name: "Services/www/"+port+"/embedded", value: TRUE);
else exit(0, "The web server listening on port "+port+" is not known to be embedded.");
