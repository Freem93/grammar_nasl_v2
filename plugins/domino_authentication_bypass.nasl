#
# This script was written by Davy Van De Moere - CISSP (davy@securax.be) 
# See the Nessus Scripts License for details
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added BugtraqID
#
# Credits go to: Gabriel A. Maggiotti (for posting this bug on qb0x.net), and 
# to Javier Fernandez-Sanguino Pena (for the look-a-like nessus script, which
# checks for anonymously accessible databases.)
# Modified by Erik Anderson <eanders@pobox.com>

# Changes by Tenable:
# - Revised plugin title (9/5/09)

include("compat.inc");

if (description)
{
 script_id(10953);
 script_version("$Revision: 1.31 $");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");

 script_cve_id("CVE-2001-1567");
 script_bugtraq_id(4022);
 script_osvdb_id(780);

 script_name(english:"IBM Lotus Domino Crafted .nsf Request Authentication Bypass");
 script_summary(english:"Checks if Lotus Domino databases can be accessed by bypassing the required authentication");

 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host has an authentication
bypass vulnerability.");
 script_set_attribute(attribute:"description", value:
"By creating a specially crafted URL, the authentication mechanism of
the Domino database can be circumvented. These URLs should look like :

  http://host.com/<databasename>.ntf<buff>.nsf/

in which <buff> has a certain length.");
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/2002/Feb/30");
 script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/2002/Feb/33");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Domino.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value:
"2002/05/12");
 script_set_attribute(attribute:"vuln_publication_date", value:"2002/02/03");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Davy Van De Moere");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


#
# The script code starts here
#
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

sig = get_http_banner(port:port);
if ( sig && "Lotus Domino" >!< sig && "Lotus-Domino" >!< sig ) exit(0);


report = string("These databases require a password, but this authentication\ncan be circumvented by supplying a long buffer in front of their name :\n");
vuln = 0;
dead = 0;

function test_cgi(port, db, db_bypass)
{
 local_var Forbidden, passed, r;

 if ( dead ) return 0;

 Forbidden = 0;

 r = http_keepalive_send_recv(port:port, data:http_get(item:db, port:port));
 if( isnull(r) ) {
	dead = 1;
	return 0;
	}
 
 if(ereg(string:r, pattern:"^HTTP/[0-9]\.[0-9] 401 .*"))
 	{
	  Forbidden = 1;
	}

 passed = 0;
 r = http_keepalive_send_recv(port:port, data:http_get(item:db_bypass, port:port));
 
 if( isnull(r) ) {
	dead = 1;
	return 0;
	}
 
 if(ereg(string:r, pattern:"^HTTP/[0-9]\.[0-9] 200 .*"))passed = 1;
 
 if((Forbidden == 1) && (passed == 1))
  {
    report = string(report, db, "\n"); 
    vuln = vuln + 1;
  }
 return(0);
}
 
 



test_cgi(port:port,
          db:"/log.nsf", 
          db_bypass:string("/log.ntf",crap(length:206,data:"+"),".nsf"));
 
test_cgi(port:port, 
          db:"/setup.nsf",
          db_bypass:string("/setup.ntf",crap(length:204,data:"+"),".nsf"));

test_cgi(port:port, 
          db:"/names.nsf",
          db_bypass:string("/names.ntf",crap(length:204,data:"+"),".nsf"));     
 
test_cgi(port:port, 
          db:"/statrep.nsf",
	  db_bypass:string("/statrep.ntf",crap(length:202,data:"+"),".nsf"));

test_cgi(port:port, 
          db:"/catalog.nsf",
          db_bypass:string("/catalog.ntf",crap(length:202,data:"+"),".nsf"));
          
test_cgi(port:port, 
          db:"/domlog.nsf",
          db_bypass:string("/domlog.ntf",crap(length:203,data:"+"),".nsf"));

test_cgi(port:port, 
          db:"/webadmin.nsf",
	  db_bypass:string("/webadmin.ntf",crap(length:201,data:"+"),".nsf"));

test_cgi(port:port, 
          db:"/cersvr.nsf",
	  db_bypass:string("/cersvr.ntf",crap(length:203,data:"+"),".nsf"));
          
test_cgi(port:port, 
          db:"/events4.nsf",
          db_bypass:string("/events4.ntf",crap(length:202,data:"+"),".nsf"));

test_cgi(port:port, 
         db:"/mab.nsf",
         db_bypass:string("/mab.ntf",crap(length:206,data:"+"),".nsf"));

test_cgi(port:port, 
         db:"/ntsync4.nsf",
         db_bypass:string("/ntsync4.ntf",crap(length:202,data:"+"),".nsf"));

test_cgi(port:port, 
         db:"/collect4.nsf",
         db_bypass:string("/collect4.ntf",crap(length:201,data:"+"),".nsf"));

test_cgi(port:port, 
        db:"/mailw46.nsf",
        db_bypass:string("/mailw46.ntf",crap(length:202,data:"+"),".nsf"));
          
test_cgi(port:port, 
        db:"/bookmark.nsf",
        db_bypass:string("/bookmark.ntf",crap(length:201,data:"+"),".nsf"));
          
test_cgi(port:port, 
          db:"/agentrunner.nsf",
          db_bypass:string("/agentrunner.ntf",crap(length:198,data:"+"),".nsf"));

test_cgi(port:port, 
          db:"/mail.box",
          db_bypass:string("/mailbox.ntf",crap(length:202,data:"+"),".nsf"));

test_cgi(port:port,
          db:"/admin4.nsf",
          db_bypass:string("/admin4.ntf",crap(length:203,data:"+"),".nsf"));

if(vuln)
  {
security_warning(port:port, extra:string(report,"\n This is a severe risk,
as an attacker is able to access \n most of the authentication protected
databases. As such, \nconfidential information can be looked into and
\nconfigurations can mostly be altered. "));
}
