#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17999);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-1033");
  script_bugtraq_id(13050);
  script_osvdb_id(15315, 15316, 15317, 15318);

  script_name(english:"CubeCart <= 2.0.6 Multiple SQL Injections");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is vulnerable to
SQL injection attacks." );
 script_set_attribute(attribute:"description", value:
"The installed version of CubeCart on the remote host suffers from
multiple SQL injection vulnerabilities due to its failure to sanitize
user input via the 'PHPSESSID' parameter of the 'index.php' script,
the 'product' parameter of the 'tellafriend.php' script, the 'add'
parameter of the 'view_cart.php' script, and the 'product' parameter
of the 'view_product.php' script.  An attacker can take advantage of
these flaws to manipulate database queries." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Apr/89" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to CubeCart 2.0.7 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/04/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/04/06");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:cubecart:cubecart");
script_end_attributes();
 
  script_summary(english:"Checks for multiple SQL injection vulnerabilities in CubeCart 2.0.6 and earlier");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("cubecart_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cubecart");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");


# These exploits should just generate syntax errors.
exploits = make_list(
  "/index.php?PHPSESSID='",
  "/tellafriend.php?product='",
  "/view_cart.php?add='",
  "/view_product.php?product='"
);


# Test an install.
install = get_kb_item(string("www/", port, "/cubecart"));
if (isnull(install)) exit(0, "cubecart was not detected on port "+port);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  foreach exploit (exploits) {
    r = http_send_recv3(method:"GET", item:string(dir, exploit), port:port, exit_on_fail: 1);
    res = r[2];

    # There's a problem if we see an error.
    if (egrep(string:res, pattern:"<b>Warning</b>: .+ in <b>.+\.php</b> on line"))
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
exit(0, "No vulnerable cubecart installation was found on port "+port);
