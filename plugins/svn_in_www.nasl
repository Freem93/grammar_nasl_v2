
# Changes by Tenable
# - Updated to use compat.inc (11/20/2009)


include("compat.inc");

if(description)
{
script_id(33821);
script_version ("$Revision: 1.13 $");

name["english"] = ".svn/entries Disclosed via Web Server";
script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"The remote web server discloses information due to a configuration
weakness." );
 script_set_attribute(attribute:"description", value:
"The web server on the remote host allows read access to '.svn/entries'
files.  This exposes all file names in your svn module on your
website. This flaw can also be used to download the source code
of the scripts (PHP, JSP, etc...) hosted on the remote server." );
 script_set_attribute(attribute:"solution", value:
"Configure permissions for the affected web server to deny access to
the '.svn' directory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  # http://techcrunch.com/2009/09/23/basic-flaw-reveals-source-code-to-3300-popular-websites/
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cdb772a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/05");
 script_cvs_date("$Date: 2016/12/14 20:33:27 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

summary["english"] = "requests .svn/entries";
script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO); 


script_copyright(english:"This script is Copyright (C) 2008-2016 Westpoint Ltd");
family["english"] = "CGI abuses";
script_family(english:family["english"]);
script_dependencie("http_version.nasl", "webmirror.nasl");
script_require_ports("Services/www", 80);
exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

dirs =  get_kb_list(string("www/", port, "/content/directories"));
if ( isnull(dirs) ) dirs = make_list();
dirs = make_list(dirs);
dirs = make_list("", dirs);
count = 0;

foreach dir ( dirs )
{
 file = string(dir, "/.svn/entries");
 req = http_get(item:file, port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( r == NULL ) exit(1, "The web server on port "+port+" failed to respond.");
 
if (
  'xmlns="svn:"' >< r || 
  "committed-rev=" >< r || 
  '\nhas-props\n' >< r ||
  egrep(pattern:"svn:(special|needs-lock)", string:r)
 )
 {
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus was able to retrieve the contents of '.svn/entries' using the\n",
      "following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:file), "\n"
    );
    if (report_verbosity > 1)
    {
     # For svn versions before 1.4 the entries file in an svn working copy was
     # an XML file. After that it's a non-XML text file with form feed (0x0c)
     # characters terminating a record. We'll reformat things a bit to make the
     # output a bit nicer.
     m = eregmatch( string:r, pattern:'^([0-9]+)' );
  
     if ( m && (m[1] >= 7) ) { # Format version >= 7
       r = str_replace( string:r, find:raw_string(0x0a), replace:'\t' );
       r = str_replace( string:r, find:raw_string(0x0c), replace:'\n' );
       r = ereg_replace( string:r, pattern:'\t+', replace:'\t' );
       r = ereg_replace( string:r, pattern:'^[0-9]+', replace:'' );
     }
     report = string(
      report,
      "\n",
      "Here is the information extracted :\n",
      "\n",
      r
     );
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
 }
 count++;
 if ( thorough_tests ) count = 0;
 if ( count >= 20 ) exit(0);
}
