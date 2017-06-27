#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23968);
  script_version("$Revision: 1.17 $");

  script_cve_id(
    "CVE-2006-4758", 
    "CVE-2006-6421", 
    "CVE-2006-6839", 
    "CVE-2006-6840", 
    "CVE-2006-6841"
 );
  script_bugtraq_id(20347, 21806, 22001);
  script_osvdb_id(
    29493,
    31859, 
    35441, 
    35442, 
    35443
 );

  script_name(english:"phpBB < 2.0.22 Multiple Vulnerabilities");
  script_summary(english:"Tries to pass a 'bad' redirect in via phpBB");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The version of phpBB installed on the remote host fails to properly
block 'bad' redirection targets.  In addition, it reportedly contains
a non-persistent cross-site scripting flaw involving its private
messaging functionality and several other issues.  At a minimum, a
remote attacker can leverage these flaws to launch cross-site
scripting attacks against the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://www.phpbb.com/phpBB/viewtopic.php?f=14&t=489624" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to phpBB 2.0.22 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/12/07");
 script_cvs_date("$Date: 2016/05/16 14:22:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:phpbb_group:phpbb");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("phpbb_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpBB");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/phpBB"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches))
{
  dir = matches[2];

  # Check whether the affected script exists.
  url = string(dir, "/login.php");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ('form action="login.php?sid=' >< res)
  {
    # Try to pass in a "bad" redirection target.
    redir = string("/", SCRIPT_NAME, ";url=", unixtime());
    postdata = string(
      "username=&",
      "password=&",
      "redirect=", redir, "&",
      "login=Log+in"
    );
    r = http_send_recv3(method: "POST", item: url, port: port,
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if the target was accepted.
    if (string('refresh" content="3;url=login.php?redirect=', redir, '">') >< res)
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
