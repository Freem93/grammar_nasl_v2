#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11685);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2013/01/25 01:19:08 $");

 script_name(english:"mod_gzip Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running mod_gzip and configured so that its status
can be obtained by sending a special request." );
 script_set_attribute(attribute:"solution", value:
"If you do not use this module, disable it completely.  

Otherwise, update the web server's configuration to limit access,
require authentication, or use a different URL associated with the
'mod_gzip_command_version' directive." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/02");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"mod_gzip detection");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "no404.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

 
port = get_http_port(default:80);

url = "/mod_gzip_status";
w = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(w)) exit(1, "the web server did not answer");
res = w[2];
if("mod_gzip_version" >< res)
{
  if (report_verbosity)
  {
    url = build_url(port:port, qs: url);
    report = string(
      "\n",
      "Nessus was able to obtain the status of mod_gzip on the remote host\n",
      "using the following URL :\n",
      "\n",
      "  ", url, "\n"
    );
    if (report_verbosity > 1)
    {
      report = string(
        report,
        "\n",
        "Here is the status :\n",
        "\n",
        res
      );
    }
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
