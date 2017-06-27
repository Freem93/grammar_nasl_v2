#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53532);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2014/08/09 00:11:22 $");

  script_cve_id(
    "CVE-2010-1917",
    "CVE-2010-2531",
    "CVE-2010-2939",
    "CVE-2010-2950",
    "CVE-2010-3709",
    "CVE-2010-4008",
    "CVE-2010-4156",
    "CVE-2011-1540",
    "CVE-2011-1541"
  );
  script_bugtraq_id(41991, 44718, 44727, 44779, 47507, 47512);
  script_osvdb_id(
    64607,
    66805,
    66086,
    66946,
    69099,
    69109,
    69205,
    73168,
    73169
);

  script_name(english:"HP System Management Homepage < 6.3 Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to the web server's banner, the version of HP System
Management Homepage (SMH) hosted on the remote host is earlier than
6.3.  Such versions are reportedly affected by the following
vulnerabilities :

  - An error exists in the function 'fnmatch' in the
    bundled version of PHP that can lead to stack
    exhaustion. (CVE-2010-1917)

  - An information disclosure vulnerability exists in the
    'var_export' function in the bundled version of PHP
    that can be triggered when handling certain error
    conditions. (CVE-2010-2531)

  - A double free vulnerability in the
    'ssl3_get_key_exchange()' function in the third-party
    OpenSSL library could be abused to crash the
    application. (CVE-2010-2939)

  - A format string vulnerability in the phar extension
    in the bundled version of PHP could lead to the
    disclosure of memory contents and possibly allow
    execution of arbitrary code via a specially crafted
    'phar://' URI. (CVE-2010-2950)

  - A NULL pointer dereference in
    'ZipArchive::getArchiveComment' included with the
    bundled version of PHP can be abused to crash the
    application. (CVE-2010-3709)

  - The bundled version of libxml2 may read from invalid
    memory locations when processing malformed XPath
    expressions, resulting in an application crash.
    (CVE-2010-4008)

  - An error in the 'mb_strcut()' function in the bundled
    version of PHP can be exploited by passing a large
    'length' parameter to disclose potentially sensitive
    information from the heap. (CVE-2010-4156)

  - An as-yet unspecified remote code execution
    vulnerability could allow an authenticated user to
    execute arbitrary code with system privileges.
    (CVE-2011-1540)

  - An as-yet unspecified, unauthorized access vulnerability
    could lead to a complete system compromise.
    (CVE-2011-1541)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/517597/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP System Management Homepage 6.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("compaq_wbem_detect.nasl");
  script_require_keys("www/hp_smh");
  script_require_ports("Services/www", 2301, 2381);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:2381, embedded:TRUE);


install = get_install_from_kb(appname:'hp_smh', port:port, exit_on_fail:TRUE);
dir = install['dir'];
version = install['ver'];
prod = get_kb_item_or_exit("www/"+port+"/hp_smh/variant");
if (version == UNKNOWN_VER)
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' is unknown.');

# nb: 'version' can have non-numeric characters in it so we'll create
#     an alternate form and make sure that's safe for use in 'ver_compare()'.
version_alt = ereg_replace(pattern:"[_-]", replace:".", string:version);
if (!ereg(pattern:"^[0-9][0-9.]+$", string:version_alt))
  exit(1, 'The version of '+prod+' installed at '+build_url(port:port, qs:dir+"/")+' does not look valid ('+version+').');

fixed_version = '6.3.0.22';
if (ver_compare(ver:version_alt, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    source_line = get_kb_item("www/"+port+"/hp_smh/source");

    report = '\n  Product           : ' + prod;
    if (!isnull(source_line))
      report += '\n  Version source    : ' + source_line;
    report +=
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, prod+" "+version+" is listening on port "+port+" and is not affected.");
