#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52717);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/20 14:21:44 $");

  script_cve_id(
    "CVE-2011-0421",
    "CVE-2011-0708",
    "CVE-2011-1092",
    "CVE-2011-1153",
    "CVE-2011-1464",
    "CVE-2011-1466",
    "CVE-2011-1467",
    "CVE-2011-1468",
    "CVE-2011-1469",
    "CVE-2011-1470"
  );
  script_bugtraq_id(46354, 46365, 46786, 46854);
  script_osvdb_id(
    71597,
    71598,
    72531,
    72532,
    72533,
    73623,
    73624,
    73625,
    73626,
    73754,
    73755
  );
  script_xref(name:"EDB-ID", value:"16261");
  script_xref(name:"Secunia", value:"43328");

  script_name(english:"PHP 5.3 < 5.3.6 Multiple Vulnerabilities");
  script_summary(english:"Checks version of PHP");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.3.x installed on the
remote host is older than 5.3.6. 

  - A NULL pointer can be dereferenced in the function
    '_zip_name_locate()' when processing empty archives and
    can lead to application crashes or code execution.
    Exploitation requires the 'ZIPARCHIVE::FL_UNCHANGED'
    setting to be in use. (CVE-2011-0421)

  - A variable casting error exists in the Exif extention,
    which can allow denial of service attacks when handling
    crafted 'Image File Directory' (IFD) header values in
    the PHP function 'exif_read_data()'. Exploitation
    requires a 64bit system and a config setting
    'memory_limit' above 4GB or unlimited. (CVE-2011-0708)

  - An integer overflow vulnerability exists in the
    implementation of the PHP function 'shmop_read()' and
    can allow arbitrary code execution. (CVE-2011-1092)

  - Errors exist in the file 'phar/phar_object.c' in which
    calls to 'zend_throw_exception_ex()' pass data as a
    string format parameter. This can lead to memory
    corruption when handling PHP archives (phar).
    (CVE-2011-1153)

  - A buffer overflow error exists in the C function
    'xbuf_format_converter' when the PHP configuration value
    for 'precision' is set to a large value and can lead to
    application crashes. (CVE-2011-1464)

  - An integer overflow error exists in the C function
    'SdnToJulian()' in the Calendar extension and can lead
    to application crashes. (CVE-2011-1466)

  - An unspecified error exists in the implementation of
    the PHP function 'numfmt_set_symbol()' and PHP method
    'NumberFormatter::setSymbol()' in the Intl extension.
    This error can lead to application crashes.
    (CVE-2011-1467)

  - Multiple memory leaks exist in the OpenSSL extension
    in the PHP functions 'openssl_encrypt' and
    'openssl_decrypt'. (CVE-2011-1468)

  - An unspecified error exists in the Streams component
    when accessing FTP URLs with an HTTP proxy.
    (CVE-2011-1469)

  - An integer signedness error and an unspecified error
    exist in the Zip extension and can lead to denial of
    service via certain ziparchive streams. (CVE-2011-1470,
    CVE-2011-1471)

  - An unspecified error exists in the security enforcement
    regarding the parsing of the fastcgi protocol with the
    'FastCGI Process Manager' (FPM) SAPI.");

  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=54193");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=54055");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=53885");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=53574");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=53512");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=54060");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=54061");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=54092");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=53579");
  script_set_attribute(attribute:"see_also", value:"http://bugs.php.net/bug.php?id=49072");
  script_set_attribute(attribute:"see_also", value:"http://openwall.com/lists/oss-security/2011/02/14/1");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_3_6.php");
  script_set_attribute(attribute:"see_also", value:"http://www.rooibo.com/2011/03/12/integer-overflow-en-php-2/");
  script_set_attribute(attribute:"solution", value:"Upgrade to PHP 5.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
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

if (version =~ '^5(\\.3)?$') exit(1, "The banner for PHP on port "+port+" - "+source+" - is not granular enough to make a determination.");

if (version =~ "^5\.3\.[0-5]($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.3.6\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
