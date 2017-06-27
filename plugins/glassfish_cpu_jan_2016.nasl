#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88022);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2016-0441", "CVE-2016-0453");
  script_osvdb_id(133199, 133209);

  script_name(english:"Oracle GlassFish Embedded Server Vulnerabilities (January 2016 CPU)");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple unspecified
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle GlassFish Server running on the remote host is
affected by multiple vulnerabilities due to unspecified flaws related
to the Embedded Server subcomponent. A remote attacker can exploit
these to impact availability, integrity, and confidentiality. No
further details have been provided by the vendor.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GlassFish Server version 3.1.2.14 or later as
referenced in the January 2016 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  # http://www.oracle.com/technetwork/topics/security/cpujan2016-2367955.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da1a16c5");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("glassfish_detect.nasl");
  script_require_keys("www/glassfish");
  script_require_ports("Services/www", 80, 4848, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

get_kb_item_or_exit("www/glassfish");

# By default, GlassFish listens on port 8080.
port = get_http_port(default:8080);

# Get the version number out of the KB.
ver = get_kb_item_or_exit("www/" + port + "/glassfish/version");
banner = get_kb_item_or_exit("www/" + port + "/glassfish/source");
pristine = get_kb_item_or_exit("www/" + port + "/glassfish/version/pristine");

# Set appropriate fixed versions.
if (ver =~ "^3\.1\.2") fix = "3.1.2.14";

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
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
