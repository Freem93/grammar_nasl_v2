#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80791);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/01/14 15:20:33 $");

  script_cve_id("CVE-2012-2733", "CVE-2012-3546", "CVE-2012-4431", "CVE-2012-4534", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887");

  script_name(english:"Oracle Solaris Third-Party Patch Update : tomcat (multiple_vulnerabilities_in_apache_tomcat3)");
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

  - java/org/apache/coyote/http11/InternalNioInputBuffer.jav
    a in the HTTP NIO connector in Apache Tomcat 6.x before
    6.0.36 and 7.x before 7.0.28 does not properly restrict
    the request-header size, which allows remote attackers
    to cause a denial of service (memory consumption) via a
    large amount of header data. (CVE-2012-2733)

  - org/apache/catalina/realm/RealmBase.java in Apache
    Tomcat 6.x before 6.0.36 and 7.x before 7.0.30, when
    FORM authentication is used, allows remote attackers to
    bypass security-constraint checks by leveraging a
    previous setUserPrincipal call and then placing
    /j_security_check at the end of a URI. (CVE-2012-3546)

  - org/apache/catalina/filters/CsrfPreventionFilter.java in
    Apache Tomcat 6.x before 6.0.36 and 7.x before 7.0.32
    allows remote attackers to bypass the cross-site request
    forgery (CSRF) protection mechanism via a request that
    lacks a session identifier. (CVE-2012-4431)

  - org/apache/tomcat/util/net/NioEndpoint.java in Apache
    Tomcat 6.x before 6.0.36 and 7.x before 7.0.28, when the
    NIO connector is used in conjunction with sendfile and
    HTTPS, allows remote attackers to cause a denial of
    service (infinite loop) by terminating the connection
    during the reading of a response. (CVE-2012-4534)

  - The replay-countermeasure functionality in the HTTP
    Digest Access Authentication implementation in Apache
    Tomcat 5.5.x before 5.5.36, 6.x before 6.0.36, and 7.x
    before 7.0.30 tracks cnonce (aka client nonce) values
    instead of nonce (aka server nonce) and nc (aka
    nonce-count) values, which makes it easier for remote
    attackers to bypass intended access restrictions by
    sniffing the network for valid requests, a different
    vulnerability than CVE-2011-1184. (CVE-2012-5885)

  - The HTTP Digest Access Authentication implementation in
    Apache Tomcat 5.5.x before 5.5.36, 6.x before 6.0.36,
    and 7.x before 7.0.30 caches information about the
    authenticated user within the session state, which makes
    it easier for remote attackers to bypass authentication
    via vectors related to the session ID. (CVE-2012-5886)

  - The HTTP Digest Access Authentication implementation in
    Apache Tomcat 5.5.x before 5.5.36, 6.x before 6.0.36,
    and 7.x before 7.0.30 does not properly check for stale
    nonce values in conjunction with enforcement of proper
    credentials, which makes it easier for remote attackers
    to bypass intended access restrictions by sniffing the
    network for valid requests. (CVE-2012-5887)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_apache_tomcat3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a0a77a1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.4.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:tomcat");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if (solaris_check_release(release:"0.5.11-0.175.1.4.0.5.0", sru:"SRU 4.5") > 0) flag++;

if (flag)
{
  set_kb_item(name:'www/0/XSRF', value:TRUE);
  error_extra = 'Affected package : tomcat\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "tomcat");
