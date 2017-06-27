#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2016:1626 and 
# Oracle Linux Security Advisory ELSA-2016-1626 respectively.
#

include("compat.inc");

if (description)
{
  script_id(93034);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/21 20:09:49 $");

  script_cve_id("CVE-2016-1000110");
  script_osvdb_id(141671);
  script_xref(name:"RHSA", value:"2016:1626");

  script_name(english:"Oracle Linux 6 / 7 : python (ELSA-2016-1626) (httpoxy)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2016:1626 :

An update for python is now available for Red Hat Enterprise Linux 6
and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Python is an interpreted, interactive, object-oriented programming
language, which includes modules, classes, exceptions, very high level
dynamic data types and dynamic typing. Python supports interfaces to
many system calls and libraries, as well as to various windowing
systems.

Security Fix(es) :

* It was discovered that the Python CGIHandler class did not properly
protect against the HTTP_PROXY variable name clash in a CGI context. A
remote attacker could possibly use this flaw to redirect HTTP requests
performed by a Python CGI script to an attacker-controlled proxy via a
malicious HTTP request. (CVE-2016-1000110)

* It was found that Python's smtplib library did not return an
exception when StartTLS failed to be established in the
SMTP.starttls() function. A man in the middle attacker could strip out
the STARTTLS command without generating an exception on the Python
SMTP client application, preventing the establishment of the TLS
layer. (CVE-2016-0772)

* It was found that the Python's httplib library (used by urllib,
urllib2 and others) did not properly check HTTPConnection.putheader()
function arguments. An attacker could use this flaw to inject
additional headers in a Python application that allowed user provided
header names or values. (CVE-2016-5699)

Red Hat would like to thank Scott Geary (VendHQ) for reporting
CVE-2016-1000110."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-August/006283.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2016-August/006284.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"python-2.6.6-66.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"python-devel-2.6.6-66.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"python-libs-2.6.6-66.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"python-test-2.6.6-66.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"python-tools-2.6.6-66.0.1.el6_8")) flag++;
if (rpm_check(release:"EL6", reference:"tkinter-2.6.6-66.0.1.el6_8")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-2.7.5-38.0.1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-debug-2.7.5-38.0.1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-devel-2.7.5-38.0.1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-libs-2.7.5-38.0.1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-test-2.7.5-38.0.1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python-tools-2.7.5-38.0.1.el7_2")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"tkinter-2.7.5-38.0.1.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debug / python-devel / python-libs / python-test / etc");
}
