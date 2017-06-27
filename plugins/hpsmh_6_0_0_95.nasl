#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46015);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/19 01:42:50 $");

  script_cve_id(
    "CVE-2008-1468",
    "CVE-2008-4226",
    "CVE-2008-5557",
    "CVE-2008-5814",
    "CVE-2009-1377",
    "CVE-2009-1378",
    "CVE-2009-1379",
    "CVE-2009-1386",
    "CVE-2009-1387",
    "CVE-2010-1034",
    "CVE-2009-4185"
  );
  script_bugtraq_id(
    28380,
    32326,
    32948,
    35001,
    35138,
    35174,
    35417,
    38081,
    39632
  );
  script_osvdb_id(
    43409,
    49993,
    51477,
    53532,
    54612,
    54613,
    54614,
    55072,
    55073,
    62109,
    64089
  );
  script_xref(name:"Secunia", value:"38341");

  script_name(english:"HP System Management Homepage < 6.0.0.96 / 6.0.0-95 Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:"The remote web server has multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the HP System
Management Homepage install on the remote host is earlier than
6.0.0.96 / 6.0.0-95.  Such versions are potentially affected by the
following vulnerabilities :

  - A cross-site scripting (XSS) vulnerability due to a
    failure to sanitize UTF-7 encoded input.  Browsers are
    only affected if encoding is set to auto-select.
    (CVE-2008-1468)

  - An integer overflow in the libxml2 library that can
    result in a heap overflow. (CVE-2008-4226)

  - A buffer overflow in the PHP mbstring extension.
    (CVE-2008-5557)

  - An unspecified XSS in PHP when 'display_errors' is
    enabled. (CVE-2008-5814)

  - Multiple denial of service vulnerabilities in OpenSSL
    DTLS. (CVE-2009-1377, CVE-2009-1378, CVE-2009-1379,
    CVE-2009-1386, CVE-2009-1387)

  - An cross-site scripting vulnerability due to a failure
    to sanitize input to the 'servercert' parameter of
    '/proxy/smhu/getuiinfo'.  (CVE-2009-4185)

  - An unspecified vulnerability that could allow an
    attacker to access sensitive information, modify data,
    or cause a denial of service. (CVE-2010-1034)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.procheckup.com/vulnerability_manager/vulnerabilities/pr09-15"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2010/Apr/205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2010/Feb/47"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2eb58026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?399c92c8"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to HP System Management Homepage 6.0.0.96 (Windows) /
6.0.0-95 (Linux) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(79, 119, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

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

# technically 6.0.0.95 is the fix for Linux and 6.0.0.96 is the fix for
# Windows, but there is no way to infer OS from the banner. since there
# is no 6.0.0.95 publicly released for Windows, this check should be
# Good Enough
fixed_version = '6.0.0.95';
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
      '\n  Fixed version     : 6.0.0.96 (Windows) / 6.0.0-95 (Linux)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, prod+" "+version+" is listening on port "+port+" and is not affected.");
