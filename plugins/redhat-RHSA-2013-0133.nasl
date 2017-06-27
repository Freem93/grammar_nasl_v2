#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0133. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63414);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2011-2722");
  script_bugtraq_id(48892);
  script_osvdb_id(76797);
  script_xref(name:"RHSA", value:"2013:0133");

  script_name(english:"RHEL 5 : hplip3 (RHSA-2013:0133)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated hplip3 packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Hewlett-Packard Linux Imaging and Printing (HPLIP) provides drivers
for Hewlett-Packard (HP) printers and multifunction peripherals.

It was found that the HP CUPS (Common UNIX Printing System) fax filter
in HPLIP created a temporary file in an insecure way. A local attacker
could use this flaw to perform a symbolic link attack, overwriting
arbitrary files accessible to a process using the fax filter (such as
the hp3-sendfax tool). (CVE-2011-2722)

This update also fixes the following bug :

* Previous modifications of the hplip3 package to allow it to be
installed alongside the original hplip package introduced several
problems to fax support; for example, the hp-sendfax utility could
become unresponsive. These problems have been fixed with this update.
(BZ#501834)

All users of hplip3 are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2722.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0133.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hpijs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip3-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip3-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hplip3-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsane-hpaio3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/08");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0133";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hpijs3-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hpijs3-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hplip3-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hplip3-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hplip3-common-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hplip3-common-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hplip3-debuginfo-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hplip3-debuginfo-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hplip3-gui-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hplip3-gui-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"hplip3-libs-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"hplip3-libs-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libsane-hpaio3-3.9.8-15.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libsane-hpaio3-3.9.8-15.el5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hpijs3 / hplip3 / hplip3-common / hplip3-debuginfo / hplip3-gui / etc");
  }
}
