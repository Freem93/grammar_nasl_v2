#
# This script was written by Nate Haggard (SecurityMetrics inc.)
#
# See the Nessus Scripts License for details

# Changes by Tenable:
# - pattern matching to determine if the file is CVS indeed [RD]
# - Revised title (12/22/08)
# - Output formatting (8/21/09)


include("compat.inc");

if(description)
{
 script_id(10922);
 script_version ("$Revision: 1.21 $");
 script_cvs_date("$Date: 2015/09/24 21:08:38 $");

 script_name(english:"CVS (Web-Based) Entries File Information Disclosure");
 script_summary(english:"requests CVS/Entries");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server allows access to a 'CVS/Entries' file and
thereby exposes file names in the associated repository." );
 script_set_attribute(attribute:"solution", value:
"Configure permissions for the affected web server to deny access to
the reported file as well other related ones, such as 'CVS/Repository'
and 'CVS/Root'." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/03/27");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_copyright(english:"This script is Copyright (C) 2002-2015 Nate Haggard (SecurityMetrics inc.)");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);

dirs =  get_kb_list(string("www/", port, "/content/directories"));
if ( isnull(dirs) ) dirs = make_list();
dirs = make_list(dirs);
dirs = make_list("", dirs);
count = 0;

foreach dir ( dirs )
{
 url = dir + '/CVS/Entries';
 req = http_get(item:url, port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if (isnull(r)) exit(1, "The web server on port "+port+" failed to respond.");

 if ('/' >!< r) continue;

 nlines = max_index(split(r));
 if (nlines == 0) continue;

 # nb: allow for one non-match, in case we don't completely read the response.
 cvs_entries = egrep(pattern:'^D?/[^/]*/[^/]*/[^/]*/[^/]*/', string:r);
 if (cvs_entries && (nlines - max_index(split(cvs_entries)) <= 1))
 {
  if (report_verbosity > 0)
  {
    report = '\n' +
      "Nessus was able to retrieve the contents of 'CVS/Entries' using the" + '\n' +
      'following URL :\n' +
      '\n' +
      '  ' + build_url(port:port, qs:url) + '\n';

    if (report_verbosity > 1)
    {
      report += '\n' +
        'Here are its contents :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        r +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
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
