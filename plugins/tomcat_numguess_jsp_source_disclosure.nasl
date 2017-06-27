#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50347);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/09 20:31:00 $");

  script_cve_id("CVE-2001-0590");
  script_bugtraq_id(2518);
  script_osvdb_id(5580);

  script_name(english:"Apache Tomcat 3.x < 3.2.2 Malformed URL JSP Source Disclosure");
  script_summary(english:"Tries to read the source of a hosted JSP script.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Apache Tomcat server is affected by a JSP source disclosure
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Apache Tomcat server is affected by an information
disclosure vulnerability which allows JSP source code to be sent as a
response to an HTTP request that does not end with an HTTP protocol
specification.

This install is also likely to be affected by a cross-site scripting
vulnerability and an additional information disclosure vulnerability,
although Nessus did not test explicitly for either of those issues."
  );
  script_set_attribute(attribute:"see_also", value:"http://tomcat.apache.org/security-4.html#Fixed_in_Apache_Tomcat_3.2.2");
  script_set_attribute(
    attribute:"see_also",
    value:"https://issues.apache.org/bugzilla/show_bug.cgi?id=748"
  );
  script_set_attribute(attribute:"solution", value:"Update to Apache Tomcat version 3.2.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2002/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("tomcat_error_version.nasl");
  script_require_ports("Services/www", 8080);
  script_require_keys("www/tomcat");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

# NB: check a couple of files in case some don't contain any JSP code
#     or include it in the generated output.
max_files = 5;
jsp_source_pat = '<(%=|@ *page|jsp:)';

files = get_kb_list("www/"+port+"/content/extensions/jsp");
if (isnull(files)) files = make_list("/index.jsp", "/examples/jsp/num/numguess.jsp");
else files = make_list(files);

n = 0;
foreach file (files)
{
  ++n;

  # Try to exploit the issue.
  soc = http_open_socket(port);
  if (!soc) exit(1, "Can't open socket on port "+port+".");

  req = 'GET ' + file + '\r\n\r\n';
  send(socket:soc, data:req);
  res = http_recv3(socket:soc);
  http_close_socket(soc);

  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  # If it looks like source...
  if (
    "Content-Type: text/plain" >< res[1] &&
    res[2] &&
    egrep(pattern:jsp_source_pat, string:res[2])
  )
  {
    # Make sure it's not normally there.
    res2 = http_send_recv3(method:"GET", item:file, port:port, exit_on_fail:TRUE);
    if (
      res2[2] &&
      !egrep(pattern:jsp_source_pat, string:res2[2])
    )
    {
      if (report_verbosity > 0)
      {
        report =
          '\n' + "Nessus was able to retrieve the source of '" + file + "' by sending" +
          '\nthe following request :' +
          '\n' +
          '\n  ' + req + '\n';

        if (report_verbosity > 1)
        {
          report +=
            '\nHere it is :' +
            '\n' +
            '\n' + crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) +
            '\n' + res[2] +
            crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      exit(0);
    }
  }

  if (n > max_files) break;
}
exit(0, "The Tomcat server listening on port "+port+" does not seem to be affected.");
