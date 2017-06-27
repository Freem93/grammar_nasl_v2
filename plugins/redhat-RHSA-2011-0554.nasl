#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0554. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54592);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2010-3493", "CVE-2011-1015", "CVE-2011-1521");
  script_bugtraq_id(44533, 46541, 47024);
  script_osvdb_id(71330);
  script_xref(name:"RHSA", value:"2011:0554");

  script_name(english:"RHEL 6 : python (RHSA-2011:0554)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated python packages that fix three security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Python is an interpreted, interactive, object-oriented programming
language.

A flaw was found in the Python urllib and urllib2 libraries where they
would not differentiate between different target URLs when handling
automatic redirects. This caused Python applications using these
modules to follow any new URL that they understood, including the
'file://' URL type. This could allow a remote server to force a local
Python application to read a local file instead of the remote one,
possibly exposing local files that were not meant to be exposed.
(CVE-2011-1521)

A race condition was found in the way the Python smtpd module handled
new connections. A remote user could use this flaw to cause a Python
script using the smtpd module to terminate. (CVE-2010-3493)

An information disclosure flaw was found in the way the Python
CGIHTTPServer module processed certain HTTP GET requests. A remote
attacker could use a specially crafted request to obtain the CGI
script's source code. (CVE-2011-1015)

This erratum also upgrades Python to upstream version 2.6.6, and
includes a number of bug fixes and enhancements. Documentation for
these bug fixes and enhancements is available from the Technical Notes
document, linked to in the References section.

All users of Python are advised to upgrade to these updated packages,
which correct these issues, and fix the bugs and add the enhancements
noted in the Technical Notes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3493.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1521.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.python.org/download/releases/2.6.6/NEWS.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0554.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0554";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-debuginfo-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-debuginfo-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-debuginfo-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-devel-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-devel-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-devel-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-docs-2.6.6-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-libs-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-libs-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-libs-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-test-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-test-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-test-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-tools-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-tools-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-tools-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tkinter-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tkinter-2.6.6-20.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tkinter-2.6.6-20.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debuginfo / python-devel / python-docs / etc");
  }
}
