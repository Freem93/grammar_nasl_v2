#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0500. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64752);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2011-2722", "CVE-2013-0200");
  script_bugtraq_id(48892);
  script_xref(name:"RHSA", value:"2013:0500");

  script_name(english:"RHEL 6 : hplip (RHSA-2013:0500)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated hplip packages that fix several security issues, multiple
bugs, and add various enhancements are now available for Red Hat
Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The hplip packages contain the Hewlett-Packard Linux Imaging and
Printing Project (HPLIP), which provides drivers for Hewlett-Packard
printers and multi-function peripherals.

Several temporary file handling flaws were found in HPLIP. A local
attacker could use these flaws to perform a symbolic link attack,
overwriting arbitrary files accessible to a process using HPLIP.
(CVE-2013-0200, CVE-2011-2722)

The CVE-2013-0200 issues were discovered by Tim Waugh of Red Hat.

The hplip packages have been upgraded to upstream version 3.12.4,
which provides a number of bug fixes and enhancements over the
previous version. (BZ#731900)

This update also fixes the following bugs :

* Previously, the hpijs package required the obsolete cupsddk-drivers
package, which was provided by the cups package. Under certain
circumstances, this dependency caused hpijs installation to fail. This
bug has been fixed and hpijs no longer requires cupsddk-drivers.
(BZ#829453)

* The configuration of the Scanner Access Now Easy (SANE) back end is
located in the /etc/sane.d/dll.d/ directory, however, the hp-check
utility checked only the /etc/sane.d/dll.conf file. Consequently,
hp-check checked for correct installation, but incorrectly reported a
problem with the way the SANE back end was installed. With this
update, hp-check properly checks for installation problems in both
locations as expected. (BZ#683007)

All users of hplip are advised to upgrade to these updated packages,
which fix these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2722.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0200.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0500.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsane-hpaio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
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
  rhsa = "RHSA-2013:0500";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hpijs-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hpijs-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hplip-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hplip-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hplip-common-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hplip-common-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hplip-debuginfo-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hplip-debuginfo-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hplip-gui-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hplip-gui-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"hplip-libs-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"hplip-libs-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libsane-hpaio-3.12.4-4.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libsane-hpaio-3.12.4-4.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs / hplip / hplip-common / hplip-debuginfo / hplip-gui / etc");
  }
}
