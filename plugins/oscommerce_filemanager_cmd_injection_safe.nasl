#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42350);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 23:21:19 $");

  script_xref(name:"EDB-ID", value:"9556");

  script_name(english:"osCommerce file_manager.php Arbitrary PHP Code Injection");
  script_summary(english:"Tries to bypass authentication and access file_manager.php");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that can be abused to
execute arbitrary PHP code."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of osCommerce hosted on the remote web server allows a
remote attacker to access the Admin filemanager utility without
authentication.  Further, this utility appears to allow arbitrary PHP
code to be stored in files under the web server's document directory
and then executed subject to the privileges under which the web server
operates.

Note that this plugin is a safe check and does not actually try to
inject arbitrary PHP code into the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"http://forums.oscommerce.com/index.php?showtopic=343958");
  script_set_attribute(
    attribute:"solution",
    value:
"Secure the osCommerce 'admin' folder by renaming it and / or defining
access controls for it.

Also, consider removing the 'file_manager.php' script."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"osCommerce 2.2 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("oscommerce_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/oscommerce");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


# Test an install.
install = get_install_from_kb(appname:'oscommerce', port:port);
if (isnull(install)) exit(1, "osCommerce wasn't detected on port "+port+".");
dir = install['dir'];


# Try to access the affected form.
#
# nb: if the admin's been renamed, we're out of luck here.
url = string(dir, "/admin/file_manager.php/login.php?action=save");

res = http_send_recv3(port:port, method:"GET", item:url);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

if (
  'Administration Tool</title>' >!< res[2] ||
  '<form name="new_file"' >!< res[2] ||
  '<input type="text" name="filename"' >!< res[2] ||
  '<textarea name="file_contents"' >!< res[2]
) exit(1, "The file_manager.php script either has been removed or could not be located / accessed via port "+port+".");


# Define some variables.
#
# nb: an empty filename will generate an error message without creating a file.
filename = "";
exploit = SCRIPT_NAME;


# Try to save a file.
postdata = string(
  "filename=", filename, "&",
  "file_contents=", urlencode(str:exploit)
);

req = http_mk_post_req(
  port        : port,
  item        : url,
  data        : postdata,
  add_headers : make_array(
    "Content-Type", "application/x-www-form-urlencoded"
  )
);
res = http_send_recv_req(port:port, req:req);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");


# There's a problem if we see an error because the filename was missing.
if (
  'Administration Tool</title>' >< res[2] &&
  'class="messageStackError"' >< res[2] &&
  "&nbsp;ERROR_FILENAME_EMPTY</td>" >< res[2]
)
{
  if (report_verbosity > 0)
  {
    report = string(
      "\n",
      "Nessus was able to verify the vulnerability using the following\n",
      "request :\n",
      "\n",
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
      http_mk_buffer_from_req(req:req), "\n",
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The osCommerce install at "+build_url(port:port, qs:dir+"/")+" is not affected.");
