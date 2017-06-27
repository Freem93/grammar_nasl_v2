#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66804);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2013-1508", "CVE-2013-1515");
  script_bugtraq_id(59143, 59151);
  script_osvdb_id(92460, 92461);

  script_name(english:"Oracle GlassFish Server 3.0.1 < 3.0.1.7 / 3.1.2 < 3.1.2.5 Multiple Vulnerabilities (April 2013 CPU)");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of GlassFish Server running on the remote host is affected
by multiple vulnerabilities :

  - Cross-site scripting (XSS) vulnerabilities exist in its
    admin and rest interface. These vulnerabilities permit
    JavaScript to be run in the context of GlassFish, which
    may result in credentials of authenticated users being
    stolen. (CVE-2013-1508, CVE-2013-1515)

  - A cross-site request forgery (CSRF) vulnerability exists
    in its REST interface. An authenticated user may be
    tricked into visiting a web page that leverages this
    vulnerability.

  - A JSF source exposure vulnerability exists that affects
    confidentiality.");
  script_set_attribute(attribute:"solution", value:"Upgrade to GlassFish Server 3.0.1.7 / 3.1.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  # http://www.oracle.com/technetwork/topics/security/cpuapr2013-1899555.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?028971b4");
  # https://blogs.oracle.com/GlassFishForBusiness/entry/oracle_glassfish_server_v3_1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ddb666a");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("glassfish_console_detect.nasl");
  script_require_keys("www/glassfish/console");
  script_require_ports("Services/www", 80, 4848, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

get_kb_item_or_exit("www/glassfish/console");

# By default, GlassFish's administration console listens on port 4848.
port = get_http_port(default:4848);

# Ensure that the console was found on this port.
get_kb_item_or_exit("www/" + port + "/glassfish/console");

# Get the version number out of the KB.
ver = get_kb_item_or_exit("www/" + port + "/glassfish/version");
banner = get_kb_item_or_exit("www/" + port + "/glassfish/source");
pristine = get_kb_item_or_exit("www/" + port + "/glassfish/version/pristine");

# Check if the installation is vulnerable.
if (ver =~ "^3\.0\.1")
  fix = "3.0.1.7";
else if (ver =~ "^3\.1\.2")
  fix = "3.1.2.5";
else
  fix = NULL;

if (!isnull(fix) && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + pristine +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Oracle GlassFish", port, pristine);
