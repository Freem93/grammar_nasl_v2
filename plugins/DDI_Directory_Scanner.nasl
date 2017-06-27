##
#   This plugin was written by H D Moore <hdm@digitaloffense.net>
##
#

# Changes by Tenable:
# - Revised plugin title (2/10/2009)
# - Added directories to look for (3/17/2009)
# - Enhanced description (4/10/2009)
# - Added 'pipermail' directory to look for (6/4/2009)

include("compat.inc");

if(description)
{
	script_id(11032);
	script_version ("$Revision: 1.110 $");

	script_xref(name:"OWASP", value:"OWASP-CM-006");

 	script_name(english: "Web Server Directory Enumeration");
 	script_summary(english:"Web Directory Scanner");

	script_set_attribute(attribute:"synopsis", value:
"It is possible to enumerate directories on the web server." );
	script_set_attribute(attribute:"description", value:
"This plugin attempts to determine the presence of various common
directories on the remote web server.  By sending a request for a
directory, the web server response code indicates if it is a valid
directory or not." );
	script_set_attribute(attribute:"solution", value:"n/a" );
	script_set_attribute(attribute:"risk_factor", value:"None" );
	script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/Predictable-Resource-Location");
	script_set_attribute(attribute:"plugin_publication_date", value:
"2002/06/26");
 script_cvs_date("$Date: 2015/10/13 15:19:32 $");
	script_set_attribute(attribute:"plugin_type", value:"remote");
	script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2002-2013 Digital Defense Inc.");
	script_family(english: "Web Servers");
	script_dependencie("find_service1.nasl", "http_login.nasl", "httpver.nasl", "embedded_web_server_detect.nasl", "waf_detection.nbin", "broken_web_server.nasl");
	script_require_ports("Services/www", 80);
	script_timeout(86400);	# timeout is managed by the script
	exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

if ( get_kb_item("Settings/disable_cgi_scanning") &&
     ! get_kb_item("Settings/enable_web_app_tests")) exit(0);

if (thorough_tests) max_timeout = 1200; # 20 min
else max_timeout = 300;			# 5 min

timeout_per_port = int(get_kb_item("Settings/HTTP/max_run_time"));
if (timeout_per_port <= 0 || timeout_per_port > max_timeout)
  timeout_per_port = max_timeout;

global_var	dirs, num_discovered;
global_var	discovered, discovered_last;
global_var 	port;

num_discovered = 0;

function check_cgi_dir(dir)
{
 local_var req, res;

 req = http_get(item:dir + "/non-existant"  + string(rand()), port:port);
 res = http_keepalive_send_recv(data:req, port:port);
 if (isnull(res))
   exit(1, "The web server on port "+port+" failed to respond.");
 if(egrep(pattern:"^HTTP.* 404 .*", string:res))
	return 1;
  else
	return 0;
}

function check_req_send(port, url)
{
 local_var req;
 local_var soc;

 soc = http_open_socket(port);
 if(!soc)return(0);
 req = http_get(item:url, port:port);
 send(socket:soc, data:req);
 return(soc);
}


function check_req_recv(soc)
{
 local_var fake404, http_resp;

 if(soc == 0)
  return(0);
  
 if(fake404 == "BadString0987654321*DDI*")
         http_resp = recv_line(socket:soc, length:255);
    else
    	 http_resp = http_recv(socket:soc);
 http_close_socket(soc);
 return(http_resp);
}



function check_dir_list (dir)
{
  local_var	CDC;
    for (CDC=0; dirs[CDC]; CDC=CDC+1)
    {
        if (dirs[CDC] == dir)
        {
            return(1);
        }
    }
    return(0);
}


function check_discovered_list (dir)
{
  local_var	CDL;

    for (CDL=0; discovered[CDL]; CDL=CDL+1)
    {
        if (discovered[CDL] == dir)
        {
            return(1);
        }
    }
    return(0);
}

function add_discovered_list (dir)
{
    if (check_discovered_list(dir:dir) == 0)
    {  
        discovered[discovered_last] = dir;
        discovered_last = discovered_last + 1;
	num_discovered ++;
        if ( num_discovered > 50 )
	  exit(1, "The web server on port "+port+" is bogus: "+ num_discovered + " directories were discovered.");
    }
}

CGI_Dirs = make_list();

i = 0;
#### Old pass #0
dirs[i++] = ".cobalt";
dirs[i++] = "Admin";
dirs[i++] = "AdminWeb";
dirs[i++] = "Admin_files";
dirs[i++] = "Administration";
dirs[i++] = "AdvWebAdmin";
dirs[i++] = "Install";
dirs[i++] = "Mail";
dirs[i++] = "News";
dirs[i++] = "PDG_Cart";
dirs[i++] = "README";
dirs[i++] = "Readme";
dirs[i++] = "Stats";
dirs[i++] = "StoreDB";
dirs[i++] = "ToDo";
dirs[i++] = "WebCalendar";
dirs[i++] = "WebTrend";
dirs[i++] = "_backup";
dirs[i++] = "_errors";
dirs[i++] = "_passwords";
dirs[i++] = "_private";
dirs[i] = "_scripts";			exec[i++] = 1;
dirs[i++] = "_tests";
dirs[i++] = "_vti_bin";
dirs[i++] = "_vti_bot";
dirs[i++] = "_vti_log";
dirs[i++] = "_vti_pvt";
dirs[i++] = "_vti_shm";
dirs[i++] = "_vti_txt";
dirs[i++] = "access";
dirs[i++] = "account";
dirs[i++] = "accounting";
dirs[i++] = "adm";
dirs[i++] = "~admin";
dirs[i++] = "admin";
dirs[i++] = "admin-bak";
dirs[i++] = "admin-old";
dirs[i++] = "admin.back";
dirs[i++] = "admin_";
dirs[i++] = "administration";
dirs[i++] = "administrator";
dirs[i++] = "adminuser";
dirs[i++] = "adminweb";
dirs[i++] = "analog";
dirs[i++] = "archive";
dirs[i++] = "archives";
dirs[i] = "asp";		exec[i++] = 1;
dirs[i++] = "auth";
dirs[i++] = "authadmin";
dirs[i++] = "backup";
dirs[i++] = "backups";
dirs[i++] = "bak";
dirs[i] = "cbi-bin";		exec[i++] = 1;
dirs[i++] = "ccard";
dirs[i++] = "ccards";
dirs[i] = "cd-cgi";		exec[i++] = 1;
dirs[i] = "cfide";		exec[i++] = 1;
dirs[i] = "cgi";		exec[i++] = 1;
dirs[i] = "cgi-auth";		exec[i++] = 1;
dirs[i] = "cgi-bin";		exec[i++] = 1;
dirs[i] = "cgi-bin2";		exec[i++] = 1;
dirs[i] = "cgi-csc";		exec[i++] = 1;
dirs[i] = "cgi-lib";		exec[i++] = 1;
dirs[i] = "cgi-local";		exec[i++] = 1;
dirs[i] = "cgi-scripts";	exec[i++] = 1;
dirs[i] = "cgi-shl";		exec[i++] = 1;
dirs[i] = "cgi-shop";		exec[i++] = 1;
dirs[i] = "cgi-sys";		exec[i++] = 1;
dirs[i] = "cgi-weddico"; 	exec[i++] = 1;
dirs[i] = "cgi-win";		exec[i++] = 1;
dirs[i] = "cgibin";		exec[i++] = 1;
dirs[i] = "cgilib";		exec[i++] = 1;
dirs[i] = "cgis";		exec[i++] = 1;
dirs[i] = "cgiscripts";		exec[i++] = 1;
dirs[i] = "cgiwin";		exec[i++] = 1;
dirs[i] = "class";		exec[i++] = 1;
dirs[i] = "classes";		exec[i++] = 1;
dirs[i++] = "config";
dirs[i++] = "credit";
dirs[i++] = "customers";
dirs[i++] = "database";
dirs[i++] = "databases";
dirs[i++] = "datafiles";
dirs[i++] = "db";
dirs[i++] = "dbase";
dirs[i++] = "demo";
dirs[i++] = "demos";
dirs[i++] = "dev";
dirs[i++] = "devel";
dirs[i++] = "directory";
dirs[i++] = "doc";
dirs[i++] = "document";
dirs[i++] = "documents";
dirs[i++] = "download";
dirs[i++] = "downloads";
dirs[i++] = "email";
dirs[i++] = "hidden";
dirs[i++] = "hlstats";
dirs[i] = "htbin";		exec[i++] = 1;
dirs[i++] = "htdocs";
dirs[i++] = "iisadmin";
dirs[i++] = "iissamples";
dirs[i++] = "include";
dirs[i++] = "includes";
dirs[i++] = "incoming";
dirs[i++] = "intranet";
dirs[i++] = "log";
dirs[i++] = "login";
dirs[i++] = "logon";
dirs[i++] = "logs";
dirs[i++] = "lost+found";
dirs[i++] = "mysql_admin";
dirs[i++] = "old";
dirs[i++] = "old_files";
dirs[i++] = "oldfiles";
dirs[i++] = "oracle";
dirs[i++] = "password";
dirs[i++] = "passwords";
dirs[i++] = "payment";
dirs[i++] = "payments";
dirs[i++] = "pipermail";
dirs[i++] = "private";
dirs[i++] = "protected";
dirs[i++] = "secret";
dirs[i++] = "secure";
dirs[i++] = "secured";
dirs[i++] = "siteadmin";
dirs[i++] = "sites";
dirs[i++] = "ssi";
dirs[i++] = "ssl";
dirs[i++] = "sslkeys";
dirs[i++] = "stat";
dirs[i++] = "statistic";
dirs[i++] = "statistics";
dirs[i++] = "stats";
dirs[i++] = "stats_old";
dirs[i++] = "sys";
dirs[i++] = "sysadmin";
dirs[i++] = "sysbackup";
dirs[i++] = "test";
dirs[i++] = "testing";
dirs[i++] = "tests";
dirs[i++] = "tmp";
dirs[i++] = "userdb";
dirs[i++] = "users";
dirs[i++] = "ustats";
dirs[i++] = "web_usage";
dirs[i++] = "webaccess";
dirs[i++] = "webadmin";
dirs[i++] = "webalizer";
dirs[i++] = "webstat";
dirs[i++] = "webstats";
dirs[i++] = "webtrends";
dirs[i++] = "wstats";
dirs[i++] = "wusage";
dirs[i++] = "wwwlog";
dirs[i++] = "wwwstat";
dirs[i++] = "wwwstats";
dirs[i++] = "~stats";
dirs[i++] = "~webstats";
dirs[i++] = "mp3";
dirs[i++] = "mp3s";
#### Old pass #1
dirs[i++] = "1";
dirs[i++] = "10";
dirs[i++] = "2";
dirs[i++] = "3";
dirs[i++] = "4";
dirs[i++] = "5";
dirs[i++] = "6";
dirs[i++] = "7";
dirs[i++] = "8";
dirs[i++] = "9";
dirs[i++] = "Agent";
dirs[i++] = "Agents";
dirs[i++] = "Album";
dirs[i++] = "CS";
dirs[i++] = "CVS";
dirs[i++] = "DMR";
dirs[i++] = "DocuColor";
dirs[i++] = "GXApp";
dirs[i++] = "HB";
dirs[i++] = "HBTemplates";
dirs[i++] = "IBMWebAS";
dirs[i++] = "JBookIt";
dirs[i++] = "Log";
dirs[i++] = "Msword";
dirs[i++] = "NSearch";
dirs[i++] = "NetDynamic";
dirs[i++] = "NetDynamics";
dirs[i++] = "ROADS";
dirs[i++] = "SilverStream";
dirs[i++] = "Templates";
dirs[i++] = "WebBank";
dirs[i++] = "WebDB";
dirs[i++] = "WebShop";
dirs[i++] = "Web_store";
dirs[i++] = "XSL";
dirs[i++] = "_ScriptLibrary";
dirs[i++] = "_derived";
dirs[i++] = "_fpclass";
dirs[i++] = "_mem_bin";
dirs[i++] = "_notes";
dirs[i++] = "_objects";
dirs[i++] = "_old";
dirs[i++] = "_pages";
dirs[i++] = "_sharedtemplates";
dirs[i++] = "_themes";
dirs[i++] = "a";
dirs[i++] = "acceso";
dirs[i++] = "accesswatch";
dirs[i++] = "acciones";
dirs[i++] = "activex";
dirs[i++] = "admcgi";
dirs[i++] = "admentor";
dirs[i++] = "admisapi";
dirs[i++] = "agentes";
dirs[i++] = "anthill";
dirs[i++] = "apache";
dirs[i++] = "app";
dirs[i++] = "applets";
dirs[i++] = "application";
dirs[i++] = "applications";
dirs[i++] = "apps";
dirs[i++] = "ar";
dirs[i++] = "atc";
dirs[i++] = "aw";
dirs[i++] = "ayuda";
dirs[i++] = "b";
dirs[i++] = "b2-include";
dirs[i++] = "back";
dirs[i++] = "backend";
dirs[i++] = "banca";
dirs[i++] = "banco";
dirs[i++] = "bank";
dirs[i++] = "banner";
dirs[i++] = "banner01";
dirs[i++] = "banners";
dirs[i++] = "batch";
dirs[i++] = "bb-dnbd";
dirs[i++] = "bbv";
dirs[i++] = "bdata";
dirs[i++] = "bdatos";
dirs[i++] = "beta";
dirs[i++] = "billpay";
dirs[i++] = "bin";
dirs[i++] = "boadmin";
dirs[i++] = "boot";
dirs[i++] = "btauxdir";
dirs[i++] = "bug";
dirs[i++] = "bugs";
dirs[i++] = "bugzilla";
dirs[i++] = "buy";
dirs[i++] = "buynow";
dirs[i++] = "c";
dirs[i++] = "cache-stats";
dirs[i++] = "caja";
dirs[i++] = "card";
dirs[i++] = "cards";
dirs[i++] = "cart";
dirs[i++] = "cash";
dirs[i++] = "caspsamp";
dirs[i++] = "catalog";
dirs[i++] = "cd";
dirs[i++] = "cdrom";
dirs[i++] = "ce_html";
dirs[i++] = "cert";
dirs[i++] = "certificado";
dirs[i++] = "certificate";
dirs[i++] = "cfappman";
dirs[i++] = "cfdocs";
dirs[i++] = "cliente";
dirs[i++] = "clientes";
dirs[i++] = "cm";
dirs[i++] = "cmsample";
dirs[i++] = "cobalt-images";
dirs[i++] = "code";
dirs[i++] = "comments";
dirs[i++] = "common";
dirs[i++] = "communicator";
dirs[i++] = "compra";
dirs[i++] = "compras";
dirs[i++] = "compressed";
dirs[i++] = "conecta";
dirs[i++] = "conf";
dirs[i++] = "connect";
dirs[i++] = "console";
dirs[i++] = "controlpanel";
dirs[i++] = "core";
dirs[i++] = "corp";
dirs[i++] = "correo";
dirs[i++] = "counter";
dirs[i++] = "cron";
dirs[i++] = "crons";
dirs[i++] = "crypto";
dirs[i++] = "csr";
dirs[i++] = "css";
dirs[i++] = "cuenta";
dirs[i++] = "cuentas";
dirs[i++] = "currency";
dirs[i++] = "cvsweb";
dirs[i++] = "cybercash";
dirs[i++] = "d";
dirs[i++] = "darkportal";
dirs[i++] = "dat";
dirs[i++] = "data";
dirs[i++] = "dato";
dirs[i++] = "datos";
dirs[i++] = "dcforum";
dirs[i++] = "ddreport";
dirs[i++] = "ddrint";
dirs[i++] = "demoauct";
dirs[i++] = "demomall";
dirs[i++] = "design";
dirs[i++] = "development";
dirs[i++] = "dir";
dirs[i++] = "directorymanager";
dirs[i++] = "dl";
dirs[i++] = "dm";
dirs[i++] = "dms";
dirs[i++] = "dms0";
dirs[i++] = "dmsdump";
dirs[i++] = "doc-html";
dirs[i++] = "doc1";
dirs[i++] = "docs";
dirs[i++] = "docs1";
dirs[i++] = "down";
dirs[i++] = "dump";
dirs[i++] = "durep";
dirs[i++] = "e";
dirs[i++] = "easylog";
dirs[i++] = "eforum";
dirs[i++] = "ejemplo";
dirs[i++] = "ejemplos";
dirs[i++] = "emailclass";
dirs[i++] = "employees";
dirs[i++] = "empoyees";
dirs[i++] = "empris";
dirs[i++] = "envia";
dirs[i++] = "enviamail";
dirs[i++] = "error";
dirs[i++] = "errors";
dirs[i++] = "es";
dirs[i++] = "estmt";
dirs[i++] = "etc";
dirs[i++] = "example";
dirs[i++] = "examples";
dirs[i++] = "exc";
dirs[i++] = "excel";
dirs[i++] = "exchange";
dirs[i++] = "exe";
dirs[i++] = "exec";
dirs[i++] = "export";
dirs[i++] = "external";
dirs[i++] = "f";
dirs[i++] = "fbsd";
dirs[i++] = "fcgi-bin";
dirs[i++] = "file";
dirs[i++] = "filemanager";
dirs[i++] = "files";
dirs[i++] = "foldoc";
dirs[i++] = "form";
dirs[i++] = "form-totaller";
dirs[i++] = "forms";
dirs[i++] = "formsmgr";
dirs[i++] = "forum";
dirs[i++] = "forums";
dirs[i++] = "foto";
dirs[i++] = "fotos";
dirs[i++] = "fpadmin";
dirs[i++] = "fpdb";
dirs[i++] = "fpsample";
dirs[i++] = "framesets";
dirs[i++] = "ftp";
dirs[i++] = "ftproot";
dirs[i++] = "g";
dirs[i++] = "gfx";
dirs[i++] = "global";
dirs[i++] = "grocery";
dirs[i++] = "guest";
dirs[i++] = "guestbook";
dirs[i++] = "guests";
dirs[i++] = "help";
dirs[i++] = "helpdesk";
dirs[i++] = "hide";
dirs[i++] = "hit_tracker";
dirs[i++] = "hitmatic";
dirs[i++] = "home";
dirs[i++] = "host-manager/html";
dirs[i++] = "hostingcontroller";
dirs[i++] = "hr";
dirs[i++] = "ht";
dirs[i++] = "html";
dirs[i++] = "hyperstat";
dirs[i++] = "ibank";
dirs[i++] = "ibill";
dirs[i++] = "icons";
dirs[i++] = "idea";
dirs[i++] = "ideas";
dirs[i++] = "image";
dirs[i++] = "imagenes";
dirs[i++] = "imagery";
dirs[i++] = "images";
dirs[i++] = "img";
dirs[i++] = "imp";
dirs[i++] = "import";
dirs[i++] = "impreso";
dirs[i++] = "inc";
dirs[i++] = "info";
dirs[i++] = "information";
dirs[i++] = "ingresa";
dirs[i++] = "ingreso";
dirs[i++] = "install";
dirs[i++] = "internal";
dirs[i++] = "inventory";
dirs[i++] = "invitado";
dirs[i++] = "isapi";
dirs[i++] = "japidoc";
dirs[i++] = "java";
dirs[i++] = "javascript";
dirs[i++] = "javasdk";
dirs[i++] = "javatest";
dirs[i++] = "jave";
dirs[i++] = "jdbc";
dirs[i++] = "job";
dirs[i++] = "jrun";
dirs[i++] = "js";
dirs[i++] = "jserv";
dirs[i++] = "jslib";
dirs[i++] = "jsp";
dirs[i++] = "jsp-examples";
dirs[i++] = "junk";
dirs[i++] = "kiva";
dirs[i++] = "labs";
dirs[i++] = "lcgi";
dirs[i++] = "lib";
dirs[i++] = "libraries";
dirs[i++] = "library";
dirs[i++] = "libro";
dirs[i++] = "links";
dirs[i++] = "linux";
dirs[i++] = "loader";
dirs[i++] = "logfile";
dirs[i++] = "logfiles";
dirs[i++] = "logg";
dirs[i++] = "logger";
dirs[i++] = "logging";
dirs[i++] = "mail";
dirs[i++] = "mail_log_files";
dirs[i++] = "mailman";
dirs[i++] = "mailroot";
dirs[i++] = "makefile";
dirs[i++] = "mall_log_files";
dirs[i++] = "manage";
dirs[i++] = "manager/html";
dirs[i++] = "manual";
dirs[i++] = "marketing";
dirs[i++] = "members";
dirs[i++] = "message";
dirs[i++] = "messaging";
dirs[i++] = "metacart";
dirs[i++] = "misc";
dirs[i++] = "mkstats";
dirs[i++] = "movimientos";
dirs[i++] = "mqseries";
dirs[i++] = "msql";
dirs[i++] = "mysql";
dirs[i++] = "ncadmin";
dirs[i++] = "nchelp";
dirs[i++] = "ncsample";
dirs[i++] = "netbasic";
dirs[i++] = "netcat";
dirs[i++] = "netmagstats";
dirs[i++] = "netscape";
dirs[i++] = "netshare";
dirs[i++] = "nettracker";
dirs[i++] = "new";
dirs[i++] = "news";
dirs[i++] = "nextgeneration";
dirs[i++] = "nl";
dirs[i++] = "noticias";
dirs[i++] = "objects";
dirs[i++] = "odbc";
dirs[i++] = "oprocmgr-service";
dirs[i++] = "oprocmgr-status";
dirs[i++] = "oradata";
dirs[i++] = "order";
dirs[i++] = "orders";
dirs[i++] = "outgoing";
dirs[i++] = "owners";
dirs[i++] = "pages";
dirs[i++] = "passport";
dirs[i++] = "pccsmysqladm";
dirs[i++] = "perl";
dirs[i++] = "perl5";
dirs[i++] = "personal";
dirs[i++] = "pforum";
dirs[i++] = "phorum";
dirs[i++] = "php";
dirs[i] = "phpBB";		exec[i++] = 1;
dirs[i] = "phpMyAdmin";		exec[i++] = 1;
dirs[i] = "phpPhotoAlbum";	exec[i++] = 1;
dirs[i] = "phpSecurePages";	exec[i++] = 1;
dirs[i] = "php_classes";	exec[i++] = 1;
dirs[i] = "phpclassifieds";	exec[i++] = 1;
dirs[i] = "phpimageview";	exec[i++] = 1;
dirs[i] = "phpnuke";		exec[i++] = 1;
dirs[i] = "phpprojekt";		exec[i++] = 1;
dirs[i++] = "piranha";
dirs[i++] = "pls";
dirs[i++] = "poll";
dirs[i++] = "polls";
dirs[i++] = "postgres";
dirs[i++] = "ppwb";
dirs[i++] = "printers";
dirs[i++] = "priv";
dirs[i++] = "privado";
dirs[i++] = "prod";
dirs[i++] = "prueba";
dirs[i++] = "pruebas";
dirs[i++] = "prv";
dirs[i++] = "pub";
dirs[i++] = "public";
dirs[i++] = "publica";
dirs[i++] = "publicar";
dirs[i++] = "publico";
dirs[i++] = "publish";
dirs[i++] = "purchase";
dirs[i++] = "purchases";
dirs[i++] = "pw";
dirs[i++] = "random_banner";
dirs[i++] = "rdp";
dirs[i++] = "register";
dirs[i++] = "registered";
dirs[i++] = "report";
dirs[i++] = "reports";
dirs[i++] = "reseller";
dirs[i++] = "restricted";
dirs[i++] = "retail";
dirs[i++] = "reviews";
dirs[i++] = "root";
dirs[i++] = "rsrc";
dirs[i++] = "sales";
dirs[i++] = "sample";
dirs[i++] = "samples";
dirs[i++] = "save";
dirs[i++] = "script";
dirs[i] = "scripts";			exec[i++] = 1;
dirs[i++] = "search";
dirs[i++] = "search-ui";
dirs[i++] = "sell";
dirs[i++] = "server-info";
dirs[i++] = "server-status";
dirs[i++] = "server_stats";
dirs[i++] = "servers";
dirs[i++] = "serverstats";
dirs[i++] = "service";
dirs[i++] = "services";
dirs[i++] = "servicio";
dirs[i++] = "servicios";
dirs[i++] = "servlet";
dirs[i++] = "servlets";
dirs[i++] = "servlets-examples";
dirs[i++] = "session";
dirs[i++] = "setup";
dirs[i++] = "share";
dirs[i++] = "shared";
dirs[i++] = "shell-cgi";
dirs[i++] = "shipping";
dirs[i++] = "shop";
dirs[i++] = "shopper";
dirs[i++] = "site";
dirs[i++] = "sitemgr";
dirs[i++] = "siteminder";
dirs[i++] = "siteminderagent";
dirs[i++] = "siteserver";
dirs[i++] = "sitestats";
dirs[i++] = "siteupdate";
dirs[i++] = "smreports";
dirs[i++] = "smreportsviewer";
dirs[i++] = "soap";
dirs[i++] = "soapdocs";
dirs[i++] = "software";
dirs[i++] = "solaris";
dirs[i++] = "source";
dirs[i++] = "sql";
dirs[i++] = "squid";
dirs[i++] = "src";
dirs[i++] = "srchadm";
dirs[i++] = "staff";
dirs[i++] = "stats-bin-p";
dirs[i++] = "status";
dirs[i++] = "storage";
dirs[i++] = "store";
dirs[i++] = "storemgr";
dirs[i++] = "stronghold-info";
dirs[i++] = "stronghold-status";
dirs[i++] = "stuff";
dirs[i++] = "style";
dirs[i++] = "styles";
dirs[i++] = "stylesheet";
dirs[i++] = "stylesheets";
dirs[i++] = "subir";
dirs[i++] = "sun";
dirs[i++] = "super_stats";
dirs[i++] = "support";
dirs[i++] = "supporter";
dirs[i++] = "system";
dirs[i++] = "tar";
dirs[i++] = "tarjetas";
dirs[i++] = "te_html";
dirs[i++] = "tech";
dirs[i++] = "technote";
dirs[i++] = "temp";
dirs[i++] = "template";
dirs[i++] = "templates";
dirs[i++] = "temporal";
dirs[i++] = "test-cgi";
dirs[i++] = "testweb";
dirs[i++] = "ticket";
dirs[i++] = "tickets";
dirs[i++] = "tools";
dirs[i++] = "tpv";
dirs[i++] = "trabajo";
dirs[i++] = "transito";
dirs[i++] = "transpolar";
dirs[i++] = "tree";
dirs[i++] = "trees";
dirs[i++] = "updates";
dirs[i++] = "upload";
dirs[i++] = "uploads";
dirs[i++] = "us";
dirs[i++] = "usage";
dirs[i++] = "user";
dirs[i++] = "usr";
dirs[i++] = "usuario";
dirs[i++] = "usuarios";
dirs[i++] = "util";
dirs[i++] = "utils";
dirs[i++] = "vfs";
dirs[i++] = "w-agora";
dirs[i++] = "w3perl";
dirs[i++] = "way-board";
dirs[i++] = "web";
dirs[i++] = "web800fo";
dirs[i++] = "webMathematica";
dirs[i++] = "webapps";
dirs[i++] = "webboard";
dirs[i++] = "webcart";
dirs[i++] = "webcart-lite";
dirs[i++] = "webdata";
dirs[i++] = "webdb";
dirs[i++] = "webimages";
dirs[i++] = "webimages2";
dirs[i++] = "weblog";
dirs[i++] = "weblogs";
dirs[i++] = "webmaster";
dirs[i++] = "webmaster_logs";
dirs[i++] = "webpub";
dirs[i++] = "webpub-ui";
dirs[i++] = "webreports";
dirs[i++] = "webreps";
dirs[i++] = "webshare";
dirs[i++] = "website";
dirs[i++] = "webtrace";
dirs[i++] = "windows";
dirs[i++] = "word";
dirs[i++] = "work";
dirs[i++] = "wsdocs";
dirs[i++] = "www";
dirs[i++] = "www-sql";
dirs[i++] = "wwwjoin";
dirs[i++] = "xGB";
dirs[i++] = "xml";
dirs[i++] = "xtemp";
dirs[i++] = "zb41";
dirs[i++] = "zipfiles";
dirs[i++] = "~1";
dirs[i++] = "~log";
dirs[i++] = "~root";
dirs[i++] = "~wsdocs";
dirs[i++] = "track";
dirs[i++] = "tracking";
dirs[i++] = "BizTalkTracking";
dirs[i++] = "BizTalkServerDocs";
dirs[i++] = "BizTalkServerRepository";
dirs[i++] = "MessagingManager";
dirs[i++] = "iisprotect";
####
dirs[i++] = "acid";
dirs[i++] = "chat";
dirs[i++] = "eManager";
dirs[i++] = "keyserver";
dirs[i++] = "search97";
dirs[i++] = "tarantella";
dirs[i++] = "webmail";
dirs[i++] = "flexcube@";
dirs[i++] = "flexcubeat";
dirs[i++] = "ganglia";
dirs[i++] = "sitebuildercontent";
dirs[i++] = "sitebuilderfiles";
dirs[i++] = "sitebuilderpictures";
dirs[i++] = "WSsamples";
dirs[i++] = "mercuryboard";
dirs[i++] = "tdbin";
dirs[i++] = "AlbumArt_";
# The three following directories exist on Resin default installation
dirs[i++] = "faq";
dirs[i++] = "ref";
dirs[i++] = "cmp";
# Phishing
dirs[i] = "cgi-bim";          exec[i++] = 1; 
# Lite-serve
dirs[i] = "cgi-isapi";		exec[i++] = 1;
# HyperWave
dirs[i++] = "wavemaster.internal";
# Urchin
dirs[i++] = "urchin";
dirs[i++] = "urchin3";
dirs[i++] = "urchin5";
# CVE-2000-0237
dirs[i++] = "publisher";
# Common Locale
dirs[i++] = "en";
dirs[i++] = "en-US";
dirs[i++] = "fr";
dirs[i++] = "intl";
# Seen on Internet
dirs[i++] = "about";
dirs[i++] = "aspx";
dirs[i++] = "Boutiques";
dirs[i++] = "business";
dirs[i++] = "content";
dirs[i++] = "Corporate";
dirs[i++] = "company";
dirs[i++] = "client";
dirs[i++] = "DB4Web";
dirs[i] = "dll";	exec[i++] = 1;
dirs[i++] = "frameset";
dirs[i++] = "howto";
dirs[i++] = "legal";
dirs[i++] = "member";
dirs[i++] = "myaccount";
dirs[i++] = "obj";
dirs[i++] = "offers";
dirs[i++] = "personal_pages";
dirs[i++] = "rem";
dirs[i++] = "Remote";
dirs[i++] = "serve";
dirs[i++] = "shopping";
dirs[i++] = "slide";
dirs[i++] = "solutions";
dirs[i++] = "v4";
dirs[i++] = "wws";		# Sympa
dirs[i++] = "squirrelmail";
dirs[i++] = "dspam";
dirs[i++] = "cacti";
#
dirs[i++] = "themes";
dirs[i++] = "xampp";
dirs[i++] = "manager";
dirs[i++] = "balancer";
dirs[i++] = "awstatstotals";
dirs[i++] = "aspnet";
dirs[i++] = "bugzilla3";

# MA 2010-01-04: the next directories were added in thorough_tests only, 
# but this is not necessary any more with the timeout per port
dirs[i++] = "lampp";
dirs[i++] = "tor";
dirs[i++] = "bbs";

# Grabbed from our specific CGI tests
dirs[i++] = "4images";
dirs[i++] = "99articles";
dirs[i++] = "DigitalScribe";
dirs[i++] = "EZPhotoSales";
dirs[i++] = "GWextranet";
dirs[i++] = "Gallery";
dirs[i++] = "IlohaMail";
dirs[i++] = "ImageVue";
dirs[i++] = "NOCC";
dirs[i++] = "OnlineViewing";
dirs[i++] = "OvCgi";
dirs[i++] = "PhpDocumentor";
dirs[i++] = "SpamConsole";
dirs[i++] = "SugarCRM";
dirs[i++] = "TXWebService";
dirs[i++] = "Wiki";
dirs[i++] = "XeroxCentreWareWeb";
dirs[i++] = "_bsLib";
dirs[i++] = "_bslib";
dirs[i++] = "aardvarktopsites";
dirs[i++] = "acal";
dirs[i++] = "actualanalyzer";
dirs[i++] = "admbook";
dirs[i++] = "ads";
dirs[i++] = "adserver";
dirs[i++] = "agenda";
dirs[i++] = "agora";
dirs[i++] = "album";
dirs[i++] = "albums";
dirs[i++] = "amazon";
dirs[i++] = "amember";
dirs[i++] = "amserver";
dirs[i++] = "angeline";
dirs[i++] = "articles";
dirs[i++] = "asteridex";
dirs[i++] = "auction";
dirs[i++] = "auktion";
dirs[i++] = "awstats";
dirs[i++] = "awstats-cgi";
dirs[i++] = "awstats/cgi-bin";
dirs[i++] = "bannerexchange";
dirs[i++] = "base";
dirs[i++] = "basilix";
dirs[i++] = "bitweaver";
dirs[i++] = "blob";
dirs[i++] = "blog";
dirs[i++] = "blogs";
dirs[i++] = "bmachine";
dirs[i++] = "board";
dirs[i++] = "boastmachine";
dirs[i++] = "boonex";
dirs[i++] = "cal";
dirs[i++] = "calendar";
dirs[i++] = "calendarexpress";
dirs[i++] = "calendarix";
dirs[i++] = "candypress";
dirs[i++] = "centreon";
dirs[i++] = "cerberus";
dirs[i++] = "cerberus-gui";
dirs[i++] = "cgi-bin/dada";
dirs[i++] = "cgi-bin/eboard40/";
dirs[i++] = "cgi-bin/mt";
dirs[i++] = "cgi-bin/openwebmail";
dirs[i++] = "cgi-bin/sysinfo";
dirs[i++] = "cgi-bin/twiki";
dirs[i++] = "cgi-bin/viewvc.cgi";
dirs[i++] = "cgi-public";
dirs[i++] = "chora";
dirs[i++] = "clan";
dirs[i++] = "clan-nic";
dirs[i++] = "claroline";
dirs[i++] = "classified";
dirs[i++] = "classifieds";
dirs[i++] = "cms";
dirs[i++] = "cms400";
dirs[i++] = "cms400.net";
dirs[i++] = "cmsmadesimple";
dirs[i++] = "cmsms";
dirs[i++] = "comersus";
dirs[i++] = "community";
dirs[i++] = "contenido";
dirs[i++] = "coppermine";
dirs[i++] = "cpg";
dirs[i++] = "crm";
dirs[i++] = "currently";
dirs[i++] = "cute";
dirs[i++] = "cutenews";
dirs[i++] = "cvstrac";
dirs[i++] = "daloradius";
dirs[i++] = "dana/fb/smb";
dirs[i++] = "discuz";
dirs[i++] = "doceboCms";
dirs[i++] = "doceboCore";
dirs[i++] = "doceboKms";
dirs[i++] = "doceboLms";
dirs[i++] = "documentation";
dirs[i++] = "docushare";
dirs[i++] = "dokeos";
dirs[i++] = "doku";
dirs[i++] = "dokuwiki";
dirs[i++] = "dolphin";
dirs[i++] = "dotProject";
dirs[i++] = "dotcms";
dirs[i++] = "dotnetnuke";
dirs[i++] = "dotproject";
dirs[i++] = "drupal";
dirs[i++] = "dsdn";
dirs[i++] = "e107";
dirs[i++] = "eAccelerator";
dirs[i++] = "eFiction";
dirs[i++] = "eaccelerator";
dirs[i++] = "easydownload";
dirs[i++] = "ecard";
dirs[i++] = "ecartis";
dirs[i++] = "ee";
dirs[i++] = "efiction";
dirs[i++] = "eggblog";
dirs[i++] = "egs";
dirs[i++] = "elog";
dirs[i++] = "esupport";
dirs[i++] = "etomite";
dirs[i++] = "events";
dirs[i++] = "exhibit";
dirs[i++] = "exhibitengine";
dirs[i++] = "exodesk";
dirs[i++] = "exoops";
dirs[i++] = "exophpdesk";
dirs[i++] = "exponent";
dirs[i++] = "fanfiction";
dirs[i++] = "fckeditor";
dirs[i++] = "feeds";
dirs[i++] = "feedsplitter";
dirs[i++] = "filemgr";
dirs[i++] = "flatnuke";
dirs[i++] = "flexcms";
dirs[i++] = "flyspeck";
dirs[i++] = "flyspray";
dirs[i++] = "forum/forum";
dirs[i++] = "forums/forum";
dirs[i++] = "fusetalk/blog";
dirs[i++] = "fusetalk/forum";
dirs[i++] = "fusion";
dirs[i++] = "fuzzylime";
dirs[i++] = "gallery";
dirs[i++] = "gb";
dirs[i++] = "gbook";
dirs[i++] = "gbs";
dirs[i++] = "gcards";
dirs[i++] = "geeklog";
dirs[i++] = "getid3";
dirs[i++] = "gf";
dirs[i++] = "gforge";
dirs[i++] = "gregarius";
dirs[i++] = "greymatter";
dirs[i++] = "guppy";
dirs[i++] = "gust";
dirs[i++] = "hc";
dirs[i++] = "hcl";
dirs[i++] = "helpDesk";
dirs[i++] = "helpcenter";
dirs[i++] = "helpcenterlive";
dirs[i++] = "horde";
dirs[i++] = "hosting_controller";
dirs[i++] = "ical";
dirs[i++] = "icalendar";
dirs[i++] = "idealbb";
dirs[i++] = "idm";
dirs[i++] = "ilohamail";
dirs[i++] = "imageVue";
dirs[i++] = "imagevue";
dirs[i++] = "imap";
dirs[i++] = "includer";
dirs[i++] = "ingo";
dirs[i++] = "interchange";
dirs[i++] = "introbuilder";
dirs[i++] = "invision";
dirs[i++] = "ipb";
dirs[i++] = "ixmail";
dirs[i++] = "jackrabbit";
dirs[i++] = "jffnms";
dirs[i++] = "jinzora";
dirs[i++] = "jira";
dirs[i++] = "joomla";
dirs[i++] = "journal";
dirs[i++] = "jukebox";
dirs[i++] = "kayako";
dirs[i++] = "klan";
dirs[i++] = "ledger";
dirs[i++] = "ledger-smb";
dirs[i++] = "ledgersmb";
dirs[i++] = "lifetype";
dirs[i++] = "limbo";
dirs[i++] = "limesurvey";
dirs[i++] = "linpha";
dirs[i++] = "lists";
dirs[i++] = "live";
dirs[i++] = "livehelp";
dirs[i++] = "logrover";
dirs[i++] = "loudblog";
dirs[i++] = "maia";
dirs[i++] = "mailguard";
dirs[i++] = "mailgust";
dirs[i++] = "maillist";
dirs[i++] = "mailscanner";
dirs[i++] = "mailserver";
dirs[i++] = "mailwatch";
dirs[i++] = "mambo";
dirs[i++] = "mantis";
dirs[i++] = "mdpro";
dirs[i++] = "mediawiki";
dirs[i++] = "mini";
dirs[i++] = "minibb";
dirs[i++] = "mnemo";
dirs[i++] = "modules/forum";
dirs[i++] = "modx";
dirs[i++] = "moinmoin";
dirs[i++] = "moodle";
dirs[i++] = "mrbs";
dirs[i++] = "mt";
dirs[i++] = "mvnforum";
dirs[i++] = "mybb";
dirs[i++] = "myreview";
dirs[i++] = "nag";
dirs[i++] = "netoffice";
dirs[i++] = "netofficedwins";
dirs[i++] = "newsfeeds";
dirs[i++] = "noahsclassifieds";
dirs[i++] = "nocc";
dirs[i++] = "nucleus";
dirs[i++] = "nuked-clan";
dirs[i++] = "nukedit";
dirs[i++] = "observer";
dirs[i++] = "ocs";
dirs[i++] = "oempro";
dirs[i++] = "oneorzero";
dirs[i++] = "onlineviewing";
dirs[i++] = "ooz";
dirs[i++] = "openads";
dirs[i++] = "openbb";
dirs[i++] = "openbiblio";
dirs[i++] = "opencart";
dirs[i++] = "openemr";
dirs[i++] = "opennms";
dirs[i++] = "opensso";
dirs[i++] = "openwebmail-cgi";
dirs[i++] = "openx";
dirs[i++] = "oramon";
dirs[i++] = "orangehrm";
dirs[i++] = "orangehrm2";
dirs[i++] = "oreon";
dirs[i++] = "original";
dirs[i++] = "oscommerce";
dirs[i++] = "ossim";
dirs[i++] = "otrs";
dirs[i++] = "owl";
dirs[i++] = "pafiledb";
dirs[i++] = "pajax";
dirs[i++] = "panews";
dirs[i++] = "pblang";
dirs[i++] = "perl-status";
dirs[i++] = "philboard";
dirs[i++] = "photo";
dirs[i++] = "photoalbum";
dirs[i++] = "photos";
dirs[i++] = "php-blogger";
dirs[i++] = "php-files";
dirs[i++] = "phpATM";
dirs[i++] = "phpAlbum";
dirs[i++] = "phpBB2";
dirs[i++] = "phpGedView";
dirs[i++] = "phpMyConferences";
dirs[i++] = "phpSysInfo";
dirs[i++] = "phpalbum";
dirs[i++] = "phpatm";
dirs[i++] = "phpauction";
dirs[i++] = "phpay";
dirs[i++] = "phpbb";
dirs[i++] = "phpblogger";
dirs[i++] = "phpcoin";
dirs[i++] = "phpdoc";
dirs[i++] = "phpdocumentor";
dirs[i++] = "phpeasydownload";
dirs[i++] = "phpfm";
dirs[i++] = "phpform";
dirs[i++] = "phpformgenerator";
dirs[i++] = "phpgedview";
dirs[i++] = "phpicalendar";
dirs[i++] = "phpkit";
dirs[i++] = "phpldapadmin";
dirs[i++] = "phplist";
dirs[i++] = "phplistpro";
dirs[i++] = "phplive";
dirs[i++] = "phplivehelper";
dirs[i++] = "phpmyadmin";
dirs[i++] = "phpmyagenda";
dirs[i++] = "phpmyconferences";
dirs[i++] = "phpmyfaq";
dirs[i++] = "phpnews";
dirs[i++] = "phppgadmin";
dirs[i++] = "phprojekt";
dirs[i++] = "phproxy";
dirs[i++] = "phpsane";
dirs[i++] = "phpslash";
dirs[i++] = "phpsupporttickets";
dirs[i++] = "phpsurveyor";
dirs[i++] = "phpsysinfo";
dirs[i++] = "phpu";
dirs[i++] = "phpupdate";
dirs[i++] = "phpwcms";
dirs[i++] = "phpwebadmin";
dirs[i++] = "phpwebgallery";
dirs[i++] = "phpwebsite";
dirs[i++] = "phpwebthings";
dirs[i++] = "phpwt";
dirs[i++] = "phpx";
dirs[i++] = "pixelpost";
dirs[i++] = "piwigo";
dirs[i++] = "pla";
dirs[i++] = "pligg";
dirs[i++] = "plog";
dirs[i++] = "plogger";
dirs[i++] = "Plone";
dirs[i++] = "plone";
dirs[i++] = "pluck";
dirs[i++] = "plume";
dirs[i++] = "pma";
dirs[i++] = "pmos";
dirs[i++] = "pmwiki";
dirs[i++] = "podcast";
dirs[i++] = "podcasts";
dirs[i++] = "pollphp";
dirs[i++] = "portal";
dirs[i++] = "portalapp";
dirs[i++] = "poster";
dirs[i++] = "poxy";
dirs[i++] = "project";
dirs[i++] = "projectpier";
dirs[i++] = "projects";
dirs[i++] = "psynch";
dirs[i++] = "ptnews";
dirs[i++] = "pubcookie";
dirs[i++] = "public_html";
dirs[i++] = "punbb";
dirs[i++] = "pwa";
dirs[i++] = "rc";
dirs[i++] = "rcblog";
dirs[i++] = "recordings";
dirs[i++] = "roller";
dirs[i++] = "roundcube";
dirs[i++] = "roundcubemail";
dirs[i++] = "rth";
dirs[i++] = "runcms";
dirs[i++] = "sane";
dirs[i++] = "sbbs";
dirs[i++] = "sblog";
dirs[i++] = "scan";
dirs[i++] = "schedule";
dirs[i++] = "scribe";
dirs[i++] = "seditio";
dirs[i++] = "segue";
dirs[i++] = "seguecms";
dirs[i++] = "sessionmanager";
dirs[i++] = "shopscript";
dirs[i++] = "shr-cgi-bin";
dirs[i++] = "silverstripe";
dirs[i++] = "simpgb";
dirs[i++] = "simplebbs";
dirs[i++] = "simplog";
dirs[i++] = "site_sift";
dirs[i++] = "sitebuilder";
dirs[i++] = "sitesift";
dirs[i++] = "sm";
dirs[i++] = "smartermail";
dirs[i++] = "smf";
dirs[i++] = "snitz";
dirs[i++] = "snmx-cgi";
dirs[i++] = "socialengine";
dirs[i++] = "socialnetwork";
dirs[i++] = "sphider";
dirs[i++] = "sphpblog";
dirs[i++] = "spip";
dirs[i++] = "spt";
dirs[i++] = "sql-ledger";
dirs[i++] = "sqlite";
dirs[i++] = "sqlitemanager";
dirs[i++] = "squirrelcart";
dirs[i++] = "sugar";
dirs[i++] = "sugarcrm";
dirs[i++] = "sugarsuite";
dirs[i++] = "support-center";
dirs[i++] = "support/helpdesk";
dirs[i++] = "supportsuite";
dirs[i++] = "survey";
dirs[i++] = "surveys";
dirs[i++] = "sympa";
dirs[i++] = "symphony";
dirs[i++] = "sysinfo";
dirs[i++] = "teaming";
dirs[i++] = "testlink";
dirs[i++] = "testsite/typo3";
dirs[i++] = "things";
dirs[i++] = "thyme";
dirs[i++] = "tigercrm";
dirs[i++] = "tiki";
dirs[i++] = "tinywebgallery";
dirs[i++] = "toplist";
dirs[i++] = "topsite";
dirs[i++] = "topsites";
dirs[i++] = "trac";
dirs[i++] = "ttforum";
dirs[i++] = "turba";
dirs[i++] = "twg";
dirs[i++] = "twiki/bin";
dirs[i++] = "typo3";
dirs[i++] = "typolight";
dirs[i++] = "ubbthreads";
dirs[i++] = "uebimiau";
dirs[i++] = "upb";
dirs[i++] = "vcard";
dirs[i++] = "vcards";
dirs[i++] = "vhcs2";
dirs[i++] = "vicidial";
dirs[i++] = "viewvc";
dirs[i++] = "viewvc.cgi";
dirs[i++] = "vtiger";
dirs[i++] = "wb";
dirs[i++] = "wbboard";
dirs[i++] = "webftp";
dirs[i++] = "webgallery";
dirs[i++] = "webinsta";
dirs[i++] = "webthings";
dirs[i++] = "wiki";
dirs[i++] = "wiki/bin";
dirs[i++] = "wikka";
dirs[i++] = "wordpress";
dirs[i++] = "wordtrans";
dirs[i++] = "wwsympa";
dirs[i++] = "x-news";
dirs[i++] = "x7chat";
dirs[i++] = "x_news";
dirs[i++] = "xampp/phpldapadmin";
dirs[i++] = "xampp/pla";
dirs[i++] = "xaraya";
dirs[i++] = "xmb";
dirs[i++] = "xnews";
dirs[i++] = "xoops";
dirs[i++] = "yabb";
dirs[i++] = "yabb2";
dirs[i++] = "yabbse";
dirs[i++] = "yapig";
dirs[i++] = "yappa";
dirs[i++] = "yappa-ng";
dirs[i++] = "zabbix";
dirs[i++] = "zboard";
dirs[i++] = "zen-cart";
dirs[i++] = "zencart";
dirs[i++] = "zenphoto";
dirs[i++] = "zen";
dirs[i++] = "zixforum";
dirs[i++] = "zpanel";
dirs[i++] = "firestats";
dirs[i++] = "jcart";
dirs[i++] = "axis2";
dirs[i++] = "swsbobje";
dirs[i++] = "imcws";
dirs[i++] = "tsweb";
#
dirs[i++] = ".bak";
dirs[i++] = "local";
dirs[i++] = "de";
dirs[i++] = "prestashop";
dirs[i++] = "easy_cms_module";
dirs[i++] = "addons";
dirs[i++] = "galleries";
dirs[i++] = "extension";
dirs[i++] = "lists/admin";
dirs[i++] = "main/inc/lib";
dirs[i++] = "JSPWiki";
dirs[i++] = "dolibarr";
dirs[i++] = "exchweb";

# Add domain name parts
hn = get_host_name();
if (! ereg(string: hn, pattern: "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"))
{
 hnp = split(hn, sep: ".");
 foreach p (hnp)
 {
   n = max_index(dirs);
   for (j = 0; j < n && dirs[j] != p; j ++)
     ;
   if (j < n) dirs[n] = p;
 }
}

# this needs to be updated to match the above list
dirs_last = i-1;

# these are the strings used by the 404 checks
e = 0;
errmsg[e++] = "not found";
errmsg[e++] = "404";
errmsg[e++] = "error has occurred";
errmsg[e++] = "FireWall-1 message";
errmsg[e++] = "Reload acp_userinfo database";
errmsg[e++] = "IMail Server Web Messaging";
errmsg[e++] = "HP Web JetAdmin";
errmsg[e++] = "Error processing SSI file";
errmsg[e++] = "ExtendNet DX Configuration";
errmsg[e++] = "Unable to complete your request due to added security features";
errmsg[e++] = "Client Authentication Remote Service</font>";
errmsg[e++] = "Error - Bad Request";
errmsg[e++] = "Webmin server";
errmsg[e++] = "unknown";
errmsg[e++] = "Management Console";
errmsg[e++] = "Insufficient Access";
errmsg[e++] = "TYPE=password";
errmsg[e++] = "The userid or password that was specified is not valid";
errmsg[e++] = "Content-Length: 0";
errmsg[e++] = "cannot be found";

debug = 0;

if(debug) display("\n::[ DDI Directory Scanner running in debug mode\n::\n");

report = string("The following directories were discovered:\n");

found = 0;

authreport = string("The following directories require authentication:\n");

authfound = 0;

fake404 = string("");
Check200 = 1;
Check401 = 1;
Check403 = 1;

# this array contains the results
discovered[0] = 0;
discovered_last = 0;

port = get_http_port(default:80);

if(!port || !get_port_state(port))
{
    if(debug) display(":: Error: port ", port, " was not open on target.\n");
    exit(0, "Port "+port+" is closed.");
}



if ( get_kb_item("Services/www/" + port + "/embedded") && ! thorough_tests )
 exit(0, "The web server on port "+port+" is embedded and the 'Perform thorough tests' setting is not enabled.");

##
# pull the robots.txt file
##



if(debug)display(":: Checking for robots.txt...\n");
req = http_get(item:"/robots.txt", port:port);
http_data = http_keepalive_send_recv(port:port, data:req);

if (ereg(pattern:"^HTTP/1.[01] 200 ", string:http_data))
{
    strings = split(http_data, keep: 0);
    foreach string (strings)
    {
      v = eregmatch(string:string, pattern: '^[ \t]*#*[ \t]*(Dis)Allow[ \t]*:[ \t]*(/[^? \t#]*)', icase: 1);
      if (! isnull(v))
        {
        robot_dir = v[2];
	# Remove trailing /
	l = strlen(robot_dir);
	while (l > 1 && robot_dir[l - 1] == '/')
	{
	 robot_dir = substr(robot_dir, 0, l - 2);
	 l --;
	}
            
            if (!check_dir_list(dir:robot_dir))
            {
                # add directory to the list
                dirs_last = dirs_last + 1;
                dirs[dirs_last] = robot_dir;
                if (debug) display(":: Directory '", robot_dir, "' added to test list\n");
            } else {
                if (debug) display(":: Directory '", robot_dir, "' already exists in test list\n");
            }
        }
    }
}


##
# pull the CVS/Entries file
##

if(debug)display(":: Checking for /CVS/Entries...\n");
req = http_get(item:"/CVS/Entries", port:port);
http_data = http_keepalive_send_recv(port:port, data:req);
if (isnull(http_data))
 exit(1, "The web server on port "+port+" failed to respond.");

if (ereg(pattern:"^HTTP/1.[01] 200 ", string:http_data))
{
    strings = split(http_data, string("\n"));
    
    foreach string (strings)
    {
        if (ereg(pattern:"^D/(.*)////", string:string, icase:TRUE))
        {
            cvs_dir = ereg_replace(pattern:"D/(.*)////.*", string:string, replace:"\1", icase:TRUE); 
            if (! check_dir_list(dir:cvs_dir))
            {
                # add directory to the list
                dirs_last = dirs_last + 1;
                dirs[dirs_last] = cvs_dir;
                if (debug) display(":: Directory '", cvs_dir, "' added to test list\n");
            } else {
                if (debug) display(":: Directory '", cvs_dir, "' already exists in test list\n");
            }
        }
    }
}


##
# test for servers which return 200/403/401 for everything
##

req = http_get(item:"/NonExistant" + rand() + "/", port:port);
http_resp = http_keepalive_send_recv(port:port, data:req);
if (isnull(http_resp))
  exit(1, "The web server on port "+port+" failed to respond.");


if(ereg(pattern:"^HTTP/1.[01] 200 ", string: http_resp))
{
    fake404 = 0;
    
    if(debug) display(":: This server returns 200 for nonexistent directories.\n");
    for(i=0;errmsg[i];i=i+1)
    {
        if (egrep(pattern:errmsg[i], string:http_resp, icase:TRUE) && !fake404)
        {
            fake404 = errmsg[i];
            if(debug) display(":: Using '", fake404, "' as an indication of a 404 error\n");
        }
    }
    
    if (!fake404)
    {
        if(debug) display(":: Could not find an error string to match against for the fake 404 response.\n");
        if(debug) display(":: Checks which rely on 200 responses are being disabled\n");
        Check200 = 0;
    }
} else {
    fake404 = string("BadString0987654321*DDI*");
}

if(ereg(pattern:"^HTTP/1.[01] 401 ", string: http_resp))
{
    if(debug) display(":: This server requires authentication for nonexistent directories, disabling 401 checks.\n");
    Check401 = 0;
}

if(ereg(pattern:"^HTTP/1.[01] 403 ", string: http_resp))
{
    if(debug) display(":: This server returns a 403 for nonexistent directories, disabling 403 checks.\n");
    Check403 = 0;
}

no403 = get_kb_item('www/no403header/'+port);
if (strlen(no403) > 0) Check403 = 0;	 
no403 = get_kb_item('www/no403body/'+port);
if (strlen(no403) > 0) Check403 = 0;	 

##
# start the actual directory scan
##

keep_scanning = 1;
ScanRootDir = "/";
max_recurse = 5;



# copy the directory test list
cdirs[0] = 0;
for (dcp=0; dirs[dcp] ; dcp=dcp+1)
{
    cdirs[dcp] = dirs[dcp];
    cdirs_last = dcp;
}


    start_pass = unixtime();
    if(debug)display(":: Starting the directory scan...\n");
    for(i = 0; cdirs[i]; i ++)
    {
        if (unixtime() - start_pass >= timeout_per_port)
	{
	  debug_print("Stopping on port ", port, " after ", timeout_per_port, " seconds\n");
	  break;
	}

	res = http_keepalive_send_recv(port:port, data:http_get(item:string(ScanRootDir, cdirs[i], "/"), port:port));
	if (isnull(res))
	  exit(1, "The web server on port "+port+" failed to respond.");
	http_code = int(substr(res, 9, 11));

	
	if(!res)res = "BogusBogusBogus";
       

        if( Check200 && 
            http_code == 200 &&
            ! (egrep(pattern:fake404, string:res, icase:TRUE))
          )
        {
            if(debug) display(":: Discovered: " , ScanRootDir, cdirs[i], "\n");

            add_discovered_list(dir:string(ScanRootDir, cdirs[i]));
	    if(exec[i] != 0){
			if(check_cgi_dir(dir:cdirs[i])) CGI_Dirs = make_list(CGI_Dirs, cdirs[i]);
			}
	    
            if(found != 0)
            {
                report = report + ", " + ScanRootDir + cdirs[i];
            } else {
                report = report + ScanRootDir + cdirs[i];
            }
            found=found+1;
        }

        if(Check403 && http_code == 403 )
        {

            if (debug) display(":: Got a 403 for ", ScanRootDir, cdirs[i], ", checking for file in the directory...\n");

            soc = check_req_send(port:port, url:string(ScanRootDir, cdirs[i], "/NonExistent.html"));
	    res2 = check_req_recv(soc:soc);
	    
            if(ereg(pattern:"^HTTP/1.[01] 403 ", string:res2))
            {
                # the whole directory appears to be protected 
                if (debug) display("::   403 applies to the entire directory \n");   
            } else {
                if (debug) display("::   403 applies to just directory indexes \n");

                # the directory just has indexes turned off
                if(debug) display(":: Discovered: " , ScanRootDir, cdirs[i], "\n");
                add_discovered_list(dir:string(ScanRootDir, cdirs[i]));
		if(exec[i] != 0)CGI_Dirs = make_list(CGI_Dirs, cdirs[i]);
		
		
                if(found != 0)
                {
                    report = report + ", " + ScanRootDir + cdirs[i];
                } else {
                    report = report + ScanRootDir + cdirs[i];
                }
                found=found+1;            
            }
        }

        if(Check401 && http_code == 401 )
        {

            if (debug) display(":: Got a 401 for ", ScanRootDir + cdirs[i], "\n");
            if(authfound != 0)
            {
                authreport = authreport + ", " + ScanRootDir + cdirs[i];
            } else {
                authreport = authreport + ScanRootDir + cdirs[i];
            }
	    num_discovered ++;
            dir_key = string("www/", port, "/content/directories/require_auth");
            if ( num_discovered > 50 ) {
			if ( defined_func("rm_kb_item"))
				rm_kb_item(name: dir_key);
			exit(1, "The web server on port "+port+" is bogus: "+ num_discovered + " directories were discovered.");
	    }
            authfound=authfound+1;            
	    set_kb_item(name:dir_key, value:string(ScanRootDir, cdirs[i]));
        }    
    }


##
# reporting happens here
##

result = string("");

if (found)
{
    result = report;
    result += string("

While this is not, in and of itself, a bug, you should manually inspect 
these directories to ensure that they are in compliance with company
security standards\n");
}

if (authfound)
{
    result = result + string("\n", authreport);
}

if (strlen(result))
{
    report = string ("\n", result);
    security_note(port:port, extra:report);

    for (idx=0; idx < discovered_last; idx=idx+1)
    {
        dir_key = string("www/", port, "/content/directories");
        if(debug) display("Setting KB key: ", dir_key, " to '", discovered[idx], "'\n");
        set_kb_item(name:dir_key, value:discovered[idx]);
    }
}



foreach d (CGI_Dirs)
{
 cgi = cgi_dirs();
 flag = 0;
 foreach c (cgi)
 {
  if(c == "/" + d) {
  	flag = 1;
	break;
	}
 }
 
 if(flag == 0)
 {
   set_kb_item(name:"/tmp/cgibin", value:"/" + d);
   set_kb_item(name: "www/"+port+"/cgibin", value:d);
 }
}
