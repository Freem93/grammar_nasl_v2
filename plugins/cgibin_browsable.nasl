#
# (C) Tenable Network Security, Inc.
#
#
# @DEPRECATED@
#
# Disabled on 1/15/2016.  Webmirror3.nbin will identify browsable
# directories.

include("compat.inc");

if(description)
{
  script_id(10039);
  script_version ("$Revision: 1.34 $");
  script_cvs_date("$Date: 2016/01/18 17:33:24 $");

  script_cve_id("CVE-1999-0569");
  script_osvdb_id(3268);
  script_xref(name:"CERT", value:"913704");

  script_name(english:"Directory Browsing Enabled on /cgi-bin (deprecated)");
  script_summary(english:"Checks for directory listing on /cgi-bin.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The /cgi-bin directory on the remote web server is browsable. An
unauthenticated, remote attacker can exploit this to disclose
sensitive information.

This plugin has been deprecated. Use webmirror3.nbin (plugin ID 10662)
instead to identify browsable directories.");
  # http://projects.webappsec.org/w/page/13246922/Directory%20Indexing
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a35179e");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"1994/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

# Deprecated.
exit(0, "Webmirror3 will identify a browsable directory.");

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

dirs = make_list("/cgi-bin", "/cgibin");
dir_lists = get_kb_list('www/'+port+'/content/directory_index');

# Exit if we've already flagged the directory.
foreach dir_list (dir_lists)
{
  foreach dir (dirs)
  {
    if (dir >< dir_list)
      exit(0, "A directory listing has already been identified on the web server at "+build_url(qs:dir_list, port:port));
  }
}

report2 = '';
count = 0;
i = 0;
snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

foreach dir (dirs)
{
  vuln = FALSE;
  url = dir + "/";

  res = http_send_recv3(
    method : "GET",
    port   : port,
    item   : url,
    exit_on_fail : TRUE
  );
  lower_res = tolower(res[2]);
  request = build_url(qs:dir, port:port);

  if (
    preg(pattern:"^.*<title>(Directory Listing For |Index of |.*- )?"+dir+"(/)?</title>", string:res[2], multiline:TRUE, icase:TRUE)
    &&
    preg(pattern:"<h(1|2)>(Directory Listing For |Index of |.*- )?"+dir+"(/)?</h(1|2)>",string:res[2],multiline:TRUE, icase:TRUE)
  )
  {
    # Apache, Oracle Application Server, lighttpd
    if (
      ">last modified<" >< lower_res &&
      ( ("parent directory</a>" >< lower_res) || (">size</" >< lower_res) )
    )
    {
      vuln = TRUE;
      count++;
    }
    # IIS
    # Regex match on tags like
    # <pre>  5/6/2013  7:44 AM        &lt;dir&gt; <A HREF
    else if
    (
      ">[to parent directory]<" >< lower_res ||
      preg(pattern:"^<pre>\s*(\d{1,2})/(\d{1,2})/(\d{4})\s*(\d{1,2}):(\d{2}).*<A HREF", string:res[2], multiline:TRUE)
     )
     {
        vuln = TRUE;
        count++;
    }
    # NGINX
    # Regex match on tags like
    # <a href="123.jpg">123.jpg</a>                 16-Jun-2013 05:46
    else if
    (
      preg(pattern:'^<a href=".*">.*</a>\\s+(\\d{2})-(\\w{3})-(\\d{4}) (\\d{2}):(\\d{2})', string:res[2], multiline:TRUE)
    )
    {
      vuln = TRUE;
      count++;
    }
    # Tomcat
    else if (
      "<strong>last modified</strong>" >< lower_res &&
      "tomcat" >< lower_res
    )
    {
      vuln = TRUE;
      count++;
    }
  }
  if (vuln)
  {
    rep_header = crap(data:"-", length:30)+' Request #' + (i + 1) +
      crap(data:"-", length:25) + '\n';
    output = strstr(res[2], "Index of");
    if (empty_or_null(output)) output = strstr(res[2], "<H1>");
    if (empty_or_null(output)) output = res[2];

    report2 +=
      '\n' + rep_header + '  ' + request + '\n'+
      '\nThis produced the following truncated response (limited to 5 lines) :'+
      '\n' + snip +
      '\n' + beginning_of_response2(resp:chomp(output), max_lines:5) +
      '\n' + snip + '\n';
      i++;
  }
}
if (empty_or_null(report2))
  audit(AUDIT_LISTEN_NOT_VULN, "web server", port);

if (report_verbosity > 0)
{
  if (count > 1)
    req = "s";
  else
    req = "";

  report =
   '\nNessus was able to identify a browsable /cgi-bin directory using the' +
   '\nfollowing request'+req+' : \n' + report2 + '\n';

  security_warning(port:port, extra:report);
}
else security_warning(port);
exit(0);
