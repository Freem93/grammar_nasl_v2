#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1265. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62090);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/05 16:17:29 $");

  script_cve_id("CVE-2011-1202", "CVE-2011-3970", "CVE-2012-2825", "CVE-2012-2870", "CVE-2012-2871", "CVE-2012-2893");
  script_bugtraq_id(46785, 47668, 51911, 54203, 55331);
  script_osvdb_id(72490, 78950, 83255, 85035, 85036, 91608);
  script_xref(name:"RHSA", value:"2012:1265");

  script_name(english:"RHEL 5 / 6 : libxslt (RHSA-2012:1265)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxslt packages that fix several security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

libxslt is a library for transforming XML files into other textual
formats (including HTML, plain text, and other XML representations of
the underlying data) using the standard XSLT stylesheet transformation
mechanism.

A heap-based buffer overflow flaw was found in the way libxslt applied
templates to nodes selected by certain namespaces. An attacker could
use this flaw to create a malicious XSL file that, when used by an
application linked against libxslt to perform an XSL transformation,
could cause the application to crash or, possibly, execute arbitrary
code with the privileges of the user running the application.
(CVE-2012-2871)

Several denial of service flaws were found in libxslt. An attacker
could use these flaws to create a malicious XSL file that, when used
by an application linked against libxslt to perform an XSL
transformation, could cause the application to crash. (CVE-2012-2825,
CVE-2012-2870, CVE-2011-3970)

An information leak could occur if an application using libxslt
processed an untrusted XPath expression, or used a malicious XSL file
to perform an XSL transformation. If combined with other flaws, this
leak could possibly help an attacker bypass intended memory corruption
protections. (CVE-2011-1202)

All libxslt users are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues. All running
applications linked against libxslt must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1202.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3970.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2825.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2870.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2871.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-2893.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1265.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxslt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxslt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxslt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxslt-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:1265";
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
  if (rpm_check(release:"RHEL5", reference:"libxslt-1.1.17-4.el5_8.3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libxslt-debuginfo-1.1.17-4.el5_8.3")) flag++;

  if (rpm_check(release:"RHEL5", reference:"libxslt-devel-1.1.17-4.el5_8.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libxslt-python-1.1.17-4.el5_8.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"libxslt-python-1.1.17-4.el5_8.3")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libxslt-python-1.1.17-4.el5_8.3")) flag++;


  if (rpm_check(release:"RHEL6", reference:"libxslt-1.1.26-2.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libxslt-debuginfo-1.1.26-2.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"libxslt-devel-1.1.26-2.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libxslt-python-1.1.26-2.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libxslt-python-1.1.26-2.el6_3.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libxslt-python-1.1.26-2.el6_3.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libxslt / libxslt-debuginfo / libxslt-devel / libxslt-python");
  }
}
