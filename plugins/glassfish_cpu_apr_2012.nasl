#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58846);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2012-0550", "CVE-2012-0551");
  script_bugtraq_id(53118, 53136);
  script_osvdb_id(
    81225,
    81226,
    81227,
    81228,
    81229,
    81230,
    81231,
    81232,
    81233,
    81234,
    81235,
    81236,
    81237,
    81250
  );
  script_xref(name:"EDB-ID", value:"18764");
  script_xref(name:"EDB-ID", value:"18766");

  script_name(english:"Oracle GlassFish Server 3.1.1 < 3.1.1.3 Multiple Vulnerabilities (April 2012 CPU)");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of GlassFish Server running on the remote host is affected
by multiple vulnerabilities :

  - A cross-site request forgery (CSRF) vulnerability in its
    REST interface. An authenticated user can be tricked
    into visiting a web page that leverages this
    vulnerability to upload an arbitrary WAR file to the
    GlassFish server, which is then executed with
    GlassFish's
    credentials. (CVE-2012-0550)

  - A cross-site scripting (XSS) vulnerability in its
    administrative interface. This vulnerability permits
    JavaScript to be run in the context of the GlassFish
    administrative interface, which may result in the
    credentials of an authenticated user being stolen for
    use in subsequent attacks. (CVE-2012-0551)");
  script_set_attribute(attribute:"solution", value:"Upgrade to GlassFish Server 3.1.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/topics/security/cpuapr2012-366314.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe94efd1");
  # http://www.security-assessment.com/files/documents/advisory/Oracle_GlassFish_Server_REST_CSRF.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a359287a");
  # http://www.security-assessment.com/files/documents/advisory/Oracle_GlassFish_Server_Multiple_XSS.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9faaa64a");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("glassfish_detect.nasl");
  script_require_keys("www/glassfish");
  script_require_ports("Services/www", 80, 4848, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");

get_kb_item_or_exit("www/glassfish");

# By default, GlassFish listens on port 8080.
port = get_http_port(default:8080);

# Get the version number out of the KB.
ver = get_kb_item_or_exit("www/" + port + "/glassfish/version");
banner = get_kb_item_or_exit("www/" + port + "/glassfish/source");
pristine = get_kb_item_or_exit("www/" + port + "/glassfish/version/pristine");

# Check if the installation is vulnerable.
if (ver =~ "^3\.1\.1")
  fix = "3.1.1.3";
else
  fix = NULL;

if (!isnull(fix) && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
    set_kb_item(name:"www/"+port+"/XSS", value:TRUE);

    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + pristine +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Oracle GlassFish", port, pristine);
