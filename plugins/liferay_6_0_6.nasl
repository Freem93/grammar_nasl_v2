#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59230);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/04/08 13:41:02 $");

  script_cve_id(
    "CVE-2011-1502",
    "CVE-2011-1503",
    "CVE-2011-1504",
    "CVE-2011-1570",
    "CVE-2011-1571"
  );
  script_bugtraq_id(47082, 73497);
  script_osvdb_id(
    73648, 
    73649, 
    73650, 
    73651, 
    73652
  );
  script_xref(name:"EDB-ID", value:"18715");

  script_name(english:"Liferay Portal < 6.0.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Liferay Portal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Liferay Portal hosted on the remote web server is affected by multiple
vulnerabilities :

  - An arbitrary file download vulnerability exists when
    Apache Tomcat is used, which allows remote,
    authenticated users to download arbitrary files via an
    entity declaration in conjunction with an entity
    reference, related to an XML External Entity (aka XXE)
    issue. (CVE-2011-1502)

  - An arbitrary file download vulnerability exists when
    Apache Tomcat or Oracle GlassFish is used. The XSL
    Content portlet allows remote, authenticated users to
    read arbitrary XSL / XML files via a file:/// URL.
    (CVE-2011-1503)

  - A cross-site scripting vulnerability exists, which
    allows remote, authenticated users to inject arbitrary
    JavaScript or HTML via a blog title. (CVE-2011-1504)

  - A cross-site scripting vulnerability exists when Apache
    Tomcat is used, which allows remote, authenticated users
    to inject arbitrary JavaScript or HTML via a message
    title. (CVE-2011-1570)

  - An unspecified vulnerability exists when Apache Tomcat
    is used. The XSL Content portlet allows remote attackers
    to execute arbitrary commands via unknown vectors.
    (CVE-2011-1571)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://openwall.com/lists/oss-security/2011/03/29/1");
   # http://issues.liferay.com/secure/ReleaseNote.jspa?version=10656&styleName=Html&projectId=10952 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5a301b1");
  script_set_attribute(attribute:"see_also", value:"http://issues.liferay.com/browse/LPS-11506");
  script_set_attribute(attribute:"see_also", value:"http://issues.liferay.com/browse/LPS-12628");
  script_set_attribute(attribute:"see_also", value:"http://issues.liferay.com/browse/LPS-13250");
  script_set_attribute(attribute:"see_also", value:"http://issues.liferay.com/browse/LPS-14726");
  script_set_attribute(attribute:"see_also", value:"http://issues.liferay.com/browse/LPS-14927");
  script_set_attribute(attribute:"see_also", value:"http://xhe.myxwiki.org/xwiki/bin/view/XSLT/Application_Liferay");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Liferay Portal 6.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("liferay_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/liferay_portal");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get the ports that web servers have been found on, defaulting to
# what Liferay uses with Tomcat, their recommended bundle.
port = get_http_port(default:8080);

# Get details of the Liferay Portal install.
install = get_install_from_kb(appname:"liferay_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];
ver = install["ver"];
url = build_url(port:port, qs:dir + "/");

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Liferay Portal", url);

# Versions earlier than 6.0.6 are vulnerable.
fix = "6.0.6";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", url, ver);

set_kb_item(name:"www/" + port + "/XSS", value:TRUE);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_hole(port:port, extra:report);
