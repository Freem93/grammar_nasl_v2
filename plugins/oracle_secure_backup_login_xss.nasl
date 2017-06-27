#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55702);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/14 20:12:25 $");

  script_cve_id("CVE-2011-2251");
  script_bugtraq_id(48757);
  script_osvdb_id(73918);
  script_xref(name:"Secunia", value:"43011");

  script_name(english:"Oracle Secure Backup Administration Server login.php XSS");
  script_summary(english:"Checks if input is fully sanitized");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server contains a PHP script that has a cross-site
scripting vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Oracle Secure Backup Administration server running on
the remote host has a cross-site scripting vulnerability.  Input to
the 'mode' parameter of login.php is not properly sanitized. 

A remote attacker could exploit this by tricking a user into
requesting a maliciously crafted URL, resulting in arbitrary script
code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7c55943"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Apply the patch referenced in Oracle's advisory."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date",value:"2011/07/19");
  script_set_attribute(attribute:"patch_publication_date",value:"2011/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/27");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:secure_backup");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:443, php:TRUE);

dir = '';
cgi = '/login.php';
unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*()-]/?=&";
xss = strcat("' injected_attribute=", unixtime());
encoded_xss = urlencode(str:xss, unreserved:unreserved);
qs = 'clear=yes&mode=' + encoded_xss;
expected_output = "name='mode' value='\" + xss + "'>";

exploited = test_cgi_xss(
  port:port,
  dirs:make_list(dir),
  cgi:cgi,
  qs:qs,
  pass_str:expected_output,
  ctrl_re:'<title>Oracle Secure Backup Web Interface</title>'
);

if (!exploited)
  exit(0, build_url(qs:dir+cgi, port:port) + " is not affected.");
