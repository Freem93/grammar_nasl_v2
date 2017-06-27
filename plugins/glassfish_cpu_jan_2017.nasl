#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96624);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/24 13:52:13 $");

  script_cve_id(
    "CVE-2016-5528",
    "CVE-2017-3239",
    "CVE-2017-3247",
    "CVE-2017-3249",
    "CVE-2017-3250"
  );
  script_bugtraq_id(
    95478,
    95480,
    95483,
    95484,
    95493
  );
  script_osvdb_id(
    150245,
    150246,
    150247,
    150248,
    150249
  );

  script_name(english:"Oracle GlassFish Server 2.1.1.x < 2.1.1.30 / 3.0.1.x < 3.0.1.15 / 3.1.2.x < 3.1.2.16 Multiple Vulnerabilities (January 2017 CPU)");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Oracle GlassFish
Server running on the remote host is 2.1.1.x prior to 2.1.1.30,
3.0.1.x prior to 3.0.1.15, or 3.1.2.x prior to 3.1.2.16. It is,
therefore, affected by multiple vulnerabilities : 

  - An unspecified flaw exists in the Security subcomponent 
    that allows an unauthenticated, remote attacker to
    execute arbitrary code. (CVE-2016-5528)

  - An unspecified flaw exists in the Administration
    subcomponent that allows a local attacker attacker to
    disclose sensitive information. Note that this
    vulnerability does not affect the 2.1.1.x version
    branch. (CVE-2017-3239)

  - An unspecified flaw exists in the Core subcomponent that
    allows an unauthenticated, remote attacker to perform
    unauthorized updates, inserts, or deletion of data over
    SMTP. (CVE-2017-3247)

  - An unspecified flaw exists in the Security subcomponent
    that allows an unauthenticated, remote attacker to
    perform unauthorized updates, inserts, or deletion of
    data over LDAP. Additionally, the attacker can
    potentially cause a partial denial of service condition.
    (CVE-2017-3249) 

  - An unspecified flaw exists in the Security subcomponent
    that allows an unauthenticated, remote attacker to
    perform unauthorized updates, inserts, or deletion of
    data over HTTP. Additionally, the attacker can
    potentially cause a partial denial of service condition.
    (CVE-2017-3250)");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2017-2881727.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?89a8e429");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GlassFish Server version 2.1.1.30 / 3.0.1.15 /
3.1.2.16 or later as referenced in the January 2017 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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
if      (ver =~ "^3\.1\.2") fix = "3.1.2.16";
else if (ver =~ "^3\.0\.1") fix = "3.0.1.15";
else if (ver =~ "^2\.1\.1") fix = "2.1.1.30";

if (!empty_or_null(ver) && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + pristine +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Oracle GlassFish", port, pristine);
