#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85298);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/20 20:49:18 $");

  script_osvdb_id(
    125849,
    125850,
    125851,
    125852,
    125853,
    125854,
    125855,
    125856,
    125859,
    126952,
    126962,
    127367
  );

  script_name(english:"PHP 5.4.x < 5.4.44 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of PHP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.4.x prior to 5.4.44. It is, therefore, affected by
multiple vulnerabilities :

  - A use-after-free error exists in file spl_dllist.c due
    to improper sanitization of input to the unserialize()
    function. An attacker can exploit this, by using a
    specially crafted SplDoublyLinkedList object, to
    deference freed memory and thus execute arbitrary code.
    (VulnDB 125849)

  - A use-after-free error exists in file spl_observer.c due
    to improper sanitization of input to the unserialize()
    function. An attacker can exploit this, by using a 
    specially crafted SplObjectStorage object, to deference
    freed memory and thus execute arbitrary code.
    (VulnDB 125850)

  - A use-after-free error exists in file spl_array.c due
    to improper sanitization of input to the unserialize()
    function. An attacker can exploit this, by using a
    specially crafted SplArrayObject object, to deference
    freed memory and thus execute arbitrary code.
    (VulnDB 125851)

  - A flaw exists in file zend_exceptions.c due to the
    improper use of the function unserialize() during
    recursive method calls. A remote attacker can exploit
    this to crash an application using PHP. (VulnDB 125852)

  - A flaw exists in file zend_exceptions.c due to
    insufficient type checking by functions unserialize()
    and __toString(). A remote attacker can exploit this to
    cause a NULL pointer deference or unexpected method
    execution, thus causing an application using PHP to
    crash. (VulnDB 125853)

  - A path traversal flaw exists in file phar_object.c due
    to improper sanitization of user-supplied input. An
    attacker can exploit this to write arbitrary files.
    (VulnDB 125854)

  - Multiple type confusion flaws exist in the _call()
    method in file php_http.c when handling calls for
    zend_hash_get_current_key or 'Z*'. An attacker can
    exploit this to disclose memory contents or crash
    an application using PHP. (VulnDB 125855)

  - A dangling pointer error exists in file spl_array.c due
    to improper sanitization of input to the unserialize()
    function. An attacker can exploit this, by using a
    specially crafted SplDoublyLinkedList object, to gain
    control over a deallocated pointer and thus execute
    arbitrary code. (VulnDB 125856)

  - The openssl_random_pseudo_bytes() function in file
    openssl.c does not generate sufficiently random numbers.
    This allows an attacker to more easily predict the
    results, thus allowing further attacks to be carried
    out. (VulnDB 125859)

  - A type confusion flaw exists in the
    serialize_function_call() function in soap.c due to
    improper validation of input passed via the header
    field. A remote attacker can exploit this to execute
    arbitrary code. (VulnDB 126952)

  - A use-after-free error exists in the session
    deserializer that is triggered when deserializing
    multiple forms of data. A remote attacker can exploit
    this to dereference already freed memory, potentially
    resulting in the execution of arbitrary code.
    (VulnDB 126962)

  - An integer truncation flaw exists in the
    zend_hash_compare() function in zend_hash.c that is
    triggered when comparing arrays. A remote attacker can
    exploit this to cause arrays to be improperly matched
    during comparison. (VulnDB 127367)
    
Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.4.44");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Aug/17");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Aug/18");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Aug/19");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=69793");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=70121");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.4.44 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

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

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.4)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.4\.") audit(AUDIT_NOT_DETECT, "PHP version 5.4.x", port);

if (version =~ "^5\.4\.([0-9]|[1-3][0-9]|4[0-3])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 5.4.44' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
