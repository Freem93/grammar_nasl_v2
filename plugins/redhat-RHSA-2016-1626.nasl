#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1626. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93039);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/01/10 20:34:13 $");

  script_cve_id("CVE-2016-1000110");
  script_osvdb_id(141671);
  script_xref(name:"RHSA", value:"2016:1626");

  script_name(english:"RHEL 6 / 7 : python (RHSA-2016:1626) (httpoxy)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for python is now available for Red Hat Enterprise Linux 6
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
    value:"https://www.redhat.com/security/data/cve/CVE-2016-1000110.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-1626.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/18");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:1626";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", reference:"python-debuginfo-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", reference:"python-devel-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", reference:"python-libs-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-test-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-test-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-test-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-tools-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-tools-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-tools-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tkinter-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tkinter-2.6.6-66.el6_8")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tkinter-2.6.6-66.el6_8")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-debug-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-debug-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"python-debuginfo-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-devel-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-devel-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", reference:"python-libs-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-test-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-test-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"python-tools-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"python-tools-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"tkinter-2.7.5-38.el7_2")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"tkinter-2.7.5-38.el7_2")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debug / python-debuginfo / python-devel / etc");
  }
}
