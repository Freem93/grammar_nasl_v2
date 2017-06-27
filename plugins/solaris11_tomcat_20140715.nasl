#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80794);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2014-0075", "CVE-2014-0096", "CVE-2014-0099", "CVE-2014-0119");

  script_name(english:"Oracle Solaris Third-Party Patch Update : tomcat (cve_2014_0075_numeric_errors)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - Integer overflow in the parseChunkHeader function in
    java/org/apache/coyote/
    http11/filters/ChunkedInputFilter.java in Apache Tomcat
    before 6.0.40, 7.x before 7.0.53, and 8.x before 8.0.4
    allows remote attackers to cause a denial of service
    (resource consumption) via a malformed chunk size in
    chunked transfer coding of a request during the
    streaming of data. (CVE-2014-0075)

  - java/org/apache/catalina/servlets/DefaultServlet.java in
    the default servlet in Apache Tomcat before 6.0.40, 7.x
    before 7.0.53, and 8.x before 8.0.4 does not properly
    restrict XSLT stylesheets, which allows remote attackers
    to bypass security-manager restrictions and read
    arbitrary files via a crafted web application that
    provides an XML external entity declaration in
    conjunction with an entity reference, related to an XML
    External Entity (XXE) issue. (CVE-2014-0096)

  - Integer overflow in
    java/org/apache/tomcat/util/buf/Ascii.java in Apache
    Tomcat before 6.0.40, 7.x before 7.0.53, and 8.x before
    8.0.4, when operated behind a reverse proxy, allows
    remote attackers to conduct HTTP request smuggling
    attacks via a crafted Content-Length HTTP header.
    (CVE-2014-0099)

  - Apache Tomcat before 6.0.40, 7.x before 7.0.54, and 8.x
    before 8.0.6 does not properly constrain the class
    loader that accesses the XML parser used with an XSLT
    stylesheet, which allows remote attackers to (1) read
    arbitrary files via a crafted web application that
    provides an XML external entity declaration in
    conjunction with an entity reference, related to an XML
    External Entity (XXE) issue, or (2) read files
    associated with different web applications on a single
    Tomcat instance via a crafted web application.
    (CVE-2014-0119)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_0075_numeric_errors
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5da2ca5d"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_0096_permissions_privileges
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1090244c"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_0099_numeric_errors
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2adec04"
  );
  # https://blogs.oracle.com/sunsecurity/entry/cve_2014_0119_permissions_privileges
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3fc37c65"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.21.4.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:tomcat");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^tomcat$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.1.21.0.4.1", sru:"SRU 11.1.21.4.1") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : tomcat\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "tomcat");
