#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99522);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/20 15:44:21 $");

  script_cve_id("CVE-2017-3626");
  script_bugtraq_id(97896);
  script_osvdb_id(155748);
  script_xref(name:"IAVA", value:"2017-A-0113");

  script_name(english:"Oracle GlassFish Server 3.1.2.x < 3.1.2.17 Java Server Faces Information Disclosure (April 2017 CPU)");
  script_summary(english:"Checks the version of Oracle GlassFish.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Oracle GlassFish Server
running on the remote host is 3.1.2.x prior to 3.1.2.17. It is,
therefore, affected by an unspecified flaw in the Java Server Faces
subcomponent that allows an unauthenticated, remote attacker to
disclose potentially sensitive information.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?623d2c22");
  # http://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/3681811.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08e1362c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle GlassFish Server version 3.1.2.17 or later as
referenced in the April 2017 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (ver =~ "^3\.1\.2") fix = "3.1.2.17";

if (!empty_or_null(ver) && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + pristine +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_NOTE);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Oracle GlassFish", port, pristine);
