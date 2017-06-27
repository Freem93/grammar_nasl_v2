#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(10484);
 script_version ("$Revision: 1.19 $");
 script_osvdb_id(383);
 script_cvs_date("$Date: 2015/09/24 21:08:40 $");

 script_name(english:"Multiple Web Server ~nobody/ Request Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"It is possible to access arbitrary files on the remote web server by
appending ~nobody/ in front of their name (as in ~nobody/etc/passwd). 

This problem is due to a misconfiguration in the web server that sets
'UserDir' or its equivalent to './'." );
 script_set_attribute(attribute:"solution", value:
"If using Apache, set 'UserDir' to 'public_html/' or something else.

If using lighttpd, upgrade to version 1.4.19 or later.

Otherwise, contact the web server vendor." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/08/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/01/01");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
 script_summary(english:"Checks for the presence of /~nobody/etc/passwd");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
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

r = http_send_recv3(method:"GET", item:"/~nobody/etc/passwd", port:port);
if (isnull(r)) exit(0);
res = r[2];

  if(egrep(pattern:".*root:.*:0:[01]:.*", string:res))
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus was able to\n",
        "read from the remote host :\n",
        "\n",
        res
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
  }
