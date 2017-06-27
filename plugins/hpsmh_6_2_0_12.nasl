#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(49272);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2009-4017",
    "CVE-2009-4018",
    "CVE-2009-4143",
    "CVE-2010-1586",
    "CVE-2010-2068",
    "CVE-2010-3009",
    "CVE-2010-3011",
    "CVE-2010-3012",
    "CVE-2010-3283",
    "CVE-2010-3284"
  );
  script_bugtraq_id(
    36935,
    37079,
    37138,
    37390,
    43208,
    43269,
    43334,
    43423,
    43462,
    43463
  );
  script_osvdb_id(
    60438,
    60451,
    61208,
    64146,
    64725,
    65654,
    68025,
    68124,
    68125,
    68216,
    68217
  );

  script_name(english:"HP System Management Homepage < 6.2 Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the HP System
Management Homepage install on the remote host is earlier than 6.2.
Such versions are reportedly affected by the following
vulnerabilities :

  - Session renegotiations are not handled properly, which
    could be exploited to insert arbitrary plaintext in a
    man-in-the-middle attack. (CVE-2009-3555)

  - An attacker may be able to upload files using a POST
    request with 'multipart/form-data' content even if the
    target script doesn't actually support file uploads per
    se. (CVE-2009-4017)

  - PHP's 'proc_open' function can be abused to bypass
    'safe_mode_allowed_env_vars' and
    'safe_mode_protected_env_vars' directives.
    (CVE-2009-4018)

  - PHP does not properly protect session data as relates
    to interrupt corruption of '$_SESSION' and the
    'session.save_path' directive. (CVE-2009-4143)

  - The application allows arbitrary URL redirections.
    (CVE-2010-1586 and CVE-2010-3283)

  - An information disclosure vulnerability exists in
    Apache's mod_proxy_ajp, mod_reqtimeout, and
    mod_proxy_http relating to timeout conditions. Note
    that this issue only affects SMH on Windows.
    (CVE-2010-2068)

  - An as-yet unspecified information disclosure
    vulnerability may allow an authorized user to gain
    access to sensitive information, which in turn could
    be leveraged to obtain root access on Linux installs
    of SMH. (CVE-2010-3009)

  - There is an as-yet unspecified HTTP response splitting
    issue. (CVE-2010-3011)

  - There is an as-yet unspecified cross-site scripting
    issue. (CVE-2010-3012)

  - An as-yet unspecified vulnerability could lead to
    remote disclosure of sensitive information.
    (CVE-2010-3284)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/513684/30/0/threaded");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/513771/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/513840/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/513917/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/513918/30/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/513920/30/0/threaded"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to HP System Management Homepage 6.2.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264, 310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/17");

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

# NB: while 6.2.0.12 is the fix for Linux and 6.2.0.13 is the fix for
#     Windows, there is no way to infer OS from the banner. Since
#     there is no 6.2.0.12 publicly released for Windows, this check
#     should be "Good Enough".
fixed_version = '6.2.0.12';

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
