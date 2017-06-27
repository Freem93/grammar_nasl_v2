#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80792);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/14 15:20:33 $");

  script_cve_id("CVE-2012-3544", "CVE-2013-2067");

  script_name(english:"Oracle Solaris Third-Party Patch Update : tomcat (multiple_vulnerabilities_in_tomcat)");
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

  - Apache Tomcat 6.x before 6.0.37 and 7.x before 7.0.30
    does not properly handle chunk extensions in chunked
    transfer coding, which allows remote attackers to cause
    a denial of service by streaming data. (CVE-2012-3544)

  - java/org/apache/catalina/authenticator/FormAuthenticator
    .java in the form authentication feature in Apache
    Tomcat 6.0.21 through 6.0.36 and 7.x before 7.0.33 does
    not properly handle the relationships between
    authentication requirements and sessions, which allows
    remote attackers to inject a request into a session by
    sending this request during completion of the login
    form, a variant of a session fixation attack.
    (CVE-2013-2067)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_tomcat
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90fb1cf3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11.1.11.4.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
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

if (solaris_check_release(release:"0.5.11-0.175.1.11.0.4.0", sru:"SRU 11.1.11.4.0") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : tomcat\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "tomcat");
