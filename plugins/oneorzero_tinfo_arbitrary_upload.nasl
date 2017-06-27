#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35261);
  script_version("$Revision: 1.9 $");

  script_bugtraq_id(32959);
  script_osvdb_id(51182);
  script_xref(name:"EDB-ID", value:"7528");

  script_name(english:"OneOrZero Helpdesk tinfo.php Arbitrary File Upload");
  script_summary(english:"Uploads an incomplete file");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an arbitrary file upload vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OneOrZero Helpdesk, a web-based helpdesk
application written in PHP. 

The version of OneOrZero HelpDesk installed on the remote host allows
uploads of arbitrary files via the 'tinfo.php' script provided the
'send_email' POST parameter is set.  By uploading a file with, say,
arbitrary PHP code, an unauthenticated, remote attacker can likely
leverage this issue to execute code subject to the privileges of the
web server user id. 

Note that successful exploitation of this issue requires that 'Task
Attachments' be enabled, which is true by default. 

Note that there is also reportedly a SQL injection issue involving the
Content_Type for uploaded files and affecting this version of
OneOrZero Helpdesk, although Nessus has not checked for it." );
 script_set_attribute(attribute:"solution", value:
"Log in to the application's control panel as the administrator and
disable 'Task Attachments' (under 'OneOrZero Settings')." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/23");
 script_cvs_date("$Date: 2011/08/31 16:56:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/ooz", "/oneorzero", "/helpdesk", "/help", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  magic = unixtime();
  url = string(dir, "/tinfo.php?id=", magic);

  # Make sure we're looking at OneOrZero Helpdesk.
  res = http_send_recv3(port:port, method:"GET", item:url);
  if (isnull(res)) exit(0);

  if (string('<B>Task #', magic, '</B>') >< res[2])
  {
    # Try to upload an incomplete file.
    bound = "nessus";
    boundary = string("--", bound);

    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="send_mail"', "\r\n",
      "\r\n",
      "1", "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="SelectedFile"; filename="nessus.php"', "\r\n",
      "Content-Type: ' text\r\n",
      "\r\n",
      # nb: without the content, the upload should fail.
      # SCRIPT_NAME, "\r\n",

      boundary, "--", "\r\n"
    );

    res = http_send_recv3(
      port        : port,
      method      : "POST", 
      item        : url, 
      data        : postdata,
      add_headers : make_array(
        "Content-Type", 
        "multipart/form-data; boundary="+bound
      )
    );
    if (isnull(res)) exit(0);

    # There's a problem if we see an error complaining about a partial upload.
    if ("The file was only partially uploaded." >< res[2])
    {
      security_hole(port);
      exit(0);
    }
  }
}
