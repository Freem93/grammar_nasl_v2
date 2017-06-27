#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84810);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/11/11 20:19:25 $");

  script_cve_id("CVE-2014-1569", "CVE-2015-2623", "CVE-2015-4744");
  script_bugtraq_id(71675, 75848, 75859);
  script_osvdb_id(115397, 124661, 124662);

  script_name(english:"Oracle GlassFish Server Multiple Vulnerabilities (July 2015 CPU)");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle GlassFish Server running on the remote host is
affected by multiple vulnerabilities :

  - A security bypass vulnerability exists in the bundled
    Network Security Services (NSS) library because the
    definite_length_decoder() function, in file quickder.c,
    does not properly form the DER encoding of an ASN.1
    length. A remote attacker, by using a long byte sequence
    for an encoding, can exploit this issue to conduct
    undetected smuggling of arbitrary data. (CVE-2014-1569)

  - An unspecified flaw exists related to the Java Server
    Faces subcomponent. A remote attacker can exploit this
    to affect the integrity of the system. (CVE-2015-2623)

  - An unspecified flaw exists related to the Java Server
    Faces and Web Container subcomponents. A remote attacker
    can exploit this to affect the integrity of the system.
    (CVE-2015-4744)");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GlassFish Server 2.1.1.26 / 3.0.1.12 / 3.1.2.12 or
later as referenced in the July 2015 Oracle Critical Patch Update
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  # http://www.oracle.com/technetwork/topics/security/cpujul2015-2367936.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d18c2a85");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
if (ver =~ "^2\.1\.1") fix = "2.1.1.26";
else if (ver =~ "^3\.0\.1") fix = "3.0.1.12";
else if (ver =~ "^3\.1\.2") fix = "3.1.2.12";
else fix = NULL;

if (!isnull(fix) && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
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
