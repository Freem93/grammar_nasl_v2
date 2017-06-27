#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1422 and 
# Oracle Linux Security Advisory ELSA-2016-1422 respectively.
#

include("compat.inc");

if (description)
{
  script_id(92397);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id("CVE-2016-5387");
  script_osvdb_id(141669);
  script_xref(name:"RHSA", value:"2016:1422");
  script_xref(name:"IAVA", value:"2017-A-0010");

  script_name(english:"Oracle Linux 7 : httpd (ELSA-2016-1422) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:1422 :

An update for httpd is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The httpd packages provide the Apache HTTP Server, a powerful,
efficient, and extensible web server.

Security Fix(es) :

* It was discovered that httpd used the value of the Proxy header from
HTTP requests to initialize the HTTP_PROXY environment variable for
CGI scripts, which in turn was incorrectly used by certain HTTP client
implementations to configure the proxy for outgoing HTTP requests. A
remote attacker could possibly use this flaw to redirect HTTP requests
performed by a CGI script to an attacker-controlled proxy via a
malicious HTTP request. (CVE-2016-5387)

Note: After this update, httpd will no longer pass the value of the
Proxy request header to scripts via the HTTP_PROXY environment
variable.

Red Hat would like to thank Scott Geary (VendHQ) for reporting this
issue.

Bug Fix(es) :

* In a caching proxy configuration, the mod_cache module would treat
content as stale if the Expires header changed when refreshing a
cached response. As a consequence, an origin server returning content
without a fixed Expires header would not be treated as cacheable. The
mod_cache module has been fixed to ignore changes in the Expires
header when refreshing content. As a result, such content is now
cacheable, improving performance and reducing load at the origin
server. (BZ#1347648)

* The HTTP status code 451 'Unavailable For Legal Reasons' was not
usable in the httpd configuration. As a consequence, modules such as
mod_rewrite could not be configured to return a 451 error if required
for legal purposes. The 451 status code has been added to the list of
available error codes, and modules can now be configured to return a
451 error if required. (BZ#1353269)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-July/006203.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_proxy_html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_session");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"httpd-2.4.6-40.0.1.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"httpd-devel-2.4.6-40.0.1.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"httpd-manual-2.4.6-40.0.1.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"httpd-tools-2.4.6-40.0.1.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_ldap-2.4.6-40.0.1.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_proxy_html-2.4.6-40.0.1.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_session-2.4.6-40.0.1.el7_2.4")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"mod_ssl-2.4.6-40.0.1.el7_2.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-devel / httpd-manual / httpd-tools / mod_ldap / etc");
}
