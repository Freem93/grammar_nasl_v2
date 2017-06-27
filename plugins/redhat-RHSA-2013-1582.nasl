#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1582. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71006);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/05 16:29:44 $");

  script_cve_id("CVE-2013-4238");
  script_bugtraq_id(61738);
  script_osvdb_id(96215);
  script_xref(name:"RHSA", value:"2013:1582");

  script_name(english:"RHEL 6 : python (RHSA-2013:1582)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated python packages that fix one security issue, several bugs, and
add one enhancement are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Python is an interpreted, interactive, object-oriented programming
language.

A flaw was found in the way the Python SSL module handled X.509
certificate fields that contain a NULL byte. An attacker could
potentially exploit this flaw to conduct man-in-the-middle attacks to
spoof SSL servers. Note that to exploit this issue, an attacker would
need to obtain a carefully crafted certificate signed by an authority
that the client trusts. (CVE-2013-4238)

These updated python packages include numerous bug fixes and one
enhancement. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All users of python are advised to upgrade to these updated packages,
which fix these issues and add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-4238.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64c6b598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-1582.html"
  );
  # https://access.redhat.com/site/documentation/en-US/Red_Hat_Enterprise_Linux
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6b506c4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:1582";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-debuginfo-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-debuginfo-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-debuginfo-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-devel-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-devel-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-devel-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-libs-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-libs-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-libs-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-test-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-test-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-test-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-tools-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-tools-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-tools-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tkinter-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tkinter-2.6.6-51.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tkinter-2.6.6-51.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debuginfo / python-devel / python-libs / etc");
  }
}
