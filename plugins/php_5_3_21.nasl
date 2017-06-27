#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63621);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/23 20:09:34 $");

  script_osvdb_id(89314);
  
  script_name(english:"PHP 5.3.x < 5.3.21 cURL X.509 Certificate Domain Name Matching MiTM Weakness");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server uses a version of PHP that is potentially
vulnerable to man-in-the-middle attacks."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its banner, the version of PHP 5.3.x installed on the
remote host is prior to 5.3.21.  It is, therefore, potentially 
affected by a weakness in the cURL extension that can allow SSL 
spoofing and man-in-the-middle attacks. 

When attempting to validate a certificate, the cURL library (libcurl)
fails to verify that a server hostname matches a domain name in an 
X.509 certificate's 'Subject Common Name' (CN) or 'SubjectAltName'.

Note that this plugin does not attempt to verify whether the PHP 
install has been built with the cURL extention, but instead relies 
only on PHP's self-reported version number."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.21");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=63352");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=63795");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP version 5.3.21 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP", "Settings/ParanoidReport");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.3)?$") exit(1, "The banner from the PHP install associated with port "+port+" - "+version+" - is not granular enough to make a determination.");
if (version !~ "^5\.3\.") audit(AUDIT_NOT_DETECT, "PHP version 5.3.x", port);

if (version =~ "^5\.3\.([0-9]|1[0-9]|20)($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : '+source +
      '\n  Installed version : '+version+
      '\n  Fixed version     : 5.3.21\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
