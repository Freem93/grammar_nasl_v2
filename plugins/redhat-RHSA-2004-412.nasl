#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2004:412. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15427);
  script_version ("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/28 17:44:45 $");

  script_cve_id("CVE-2004-0689", "CVE-2004-0721", "CVE-2004-0746", "CVE-2004-0866", "CVE-2004-0867");
  script_osvdb_id(8589, 9117, 10002, 59838);
  script_xref(name:"RHSA", value:"2004:412");

  script_name(english:"RHEL 2.1 / 3 : kdelibs, kdebase (RHSA-2004:412)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelib and kdebase packages that resolve multiple security
issues are now available.

The kdelibs packages include libraries for the K Desktop Environment.
The kdebase packages include core applications for the K Desktop
Environment.

Andrew Tuitt reported that versions of KDE up to and including 3.2.3
create temporary directories with predictable names. A local attacker
could prevent KDE applications from functioning correctly, or
overwrite files owned by other users by creating malicious symlinks.
The Common Vulnerabilities and Exposures project has assigned the name
CVE-2004-0689 to this issue.

WESTPOINT internet reconnaissance services has discovered that the KDE
web browser Konqueror allows websites to set cookies for certain
country specific secondary top level domains. An attacker within one
of the affected domains could construct a cookie which would be sent
to all other websites within the domain leading to a session fixation
attack. This issue does not affect popular domains such as .co.uk,
.co.in, or .com. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2004-0721 to this issue.

A frame injection spoofing vulnerability has been discovered in the
Konqueror web browser. This issue could allow a malicious website to
show arbitrary content in a named frame of a different browser window.
The Common Vulnerabilities and Exposures project has assigned the name
CVE-2004-0746 to this issue.

All users of KDE are advised to upgrade to these erratum packages,
which contain backported patches from the KDE team for these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0689.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0721.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2004-0746.html"
  );
  # http://secunia.com/multiple_browsers_frame_injection_vulnerability_test/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b658087"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2004-412.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:arts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-sound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-sound-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/10/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2004:412";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"arts-2.2.2-13")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdebase-2.2.2-12")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdebase-devel-2.2.2-12")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-2.2.2-13")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-devel-2.2.2-13")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-sound-2.2.2-13")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"kdelibs-sound-devel-2.2.2-13")) flag++;

  if (rpm_check(release:"RHEL3", reference:"kdebase-3.1.3-5.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kdebase-devel-3.1.3-5.4")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kdelibs-3.1.3-6.6")) flag++;
  if (rpm_check(release:"RHEL3", reference:"kdelibs-devel-3.1.3-6.6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "arts / kdebase / kdebase-devel / kdelibs / kdelibs-devel / etc");
  }
}
