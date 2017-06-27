#
# (C) Tenable Network Security, Inc.
# 


include("compat.inc");

if(description)
{
 script_id(10402);
 script_version ("$Revision: 1.26 $");
 script_cvs_date("$Date: 2011/03/14 21:48:02 $");

 script_name(english:"CVSweb Detection");
 script_set_attribute(attribute:"synopsis", value:
"The remote web server host the 'cvsweb' CGI." );
 script_set_attribute(attribute:"description", value:
"CVSweb is a web interface for a CVS repository.  It allows users to
browse through the history of the source code of a given project. 

If your environement contains sensitive source code, then access to
this CGI should be password-protected." );
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"solution", value: "n/a");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


 summary["english"] = "Determines whether cvsweb.cgi is installed on the remote host";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80 );

foreach dir ( cgi_dirs() )
{
 r = http_send_recv3(method:"GET", item:dir + '/cvsweb.cgi/', port:port);
 if (isnull(r)) exit(0);

 generator = egrep(pattern:'<meta name="generator" content=', string:r[2]);
 if ( ! generator ) exit(0);
 if ( "CVSweb" >< generator )
 {
   version = ereg_replace(pattern:'.*content="(.*)".*', string:generator, replace:"\1");
   report = 'CVSweb version : ' + version;
   set_kb_item(name:"www/" + port + "/cvsweb/version", value:version);
   security_note(port:port, extra:report);
 }
}
