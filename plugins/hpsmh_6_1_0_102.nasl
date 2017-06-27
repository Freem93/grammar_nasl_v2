#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46677);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/10/27 15:03:53 $");

  script_cve_id("CVE-2009-3555");
  script_bugtraq_id(36935);
  script_osvdb_id(64725);
  script_xref(name:"Secunia", value:"39777");

  script_name(english:"HP System Management Homepage < 6.1.0.102 / 6.1.0-103 Multiple Vulnerabilities");
  script_summary(english:"Does a banner check");

  script_set_attribute(attribute:"synopsis", value:"The remote web server has multiple vulnerabilities.");
  script_set_attribute(
    attribute:"description",
    value:
"According to the web server banner, the version of HP System
Management Homepage (SMH) running on the remote host is potentially
affected by the following vulnerabilities :

  - Session renegotiations are not handled properly, which
    could be exploited to insert arbitrary plaintext by a
    man-in-the-middle. (CVE-2009-3555)

  - An unspecified vulnerability in version 2.0.18 of the
    Namazu component, used by the Windows version of SMH."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/May/139");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e8707ba"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to HP System Management Homepage 6.1.0.102 (Windows) /
6.1.0-103 (Linux) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");

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

# technically 6.1.0.103 is the fix for Linux and 6.1.0.102 is the fix for
# Windows, but there is no way to infer OS from the banner. since there
# is no 6.1.0.102 publicly released for Linux, this check should be
# Good Enough
fixed_version = '6.1.0.102';
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
      '\n  Fixed version     : 6.1.0.102 (Windows) / 6.1.0-103 (Linux)\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, prod+" "+version+" is listening on port "+port+" and is not affected.");
