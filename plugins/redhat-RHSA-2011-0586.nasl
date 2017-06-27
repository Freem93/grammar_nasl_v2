#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0586. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63981);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2010-3851");
  script_bugtraq_id(44166);
  script_xref(name:"RHSA", value:"2011:0586");

  script_name(english:"RHEL 6 : libguestfs (RHSA-2011:0586)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libguestfs packages that fix one security issue, several bugs,
and add one enhancement are now available for Red Hat Enterprise Linux
6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

libguestfs is a library for accessing and modifying guest disk images.

libguestfs relied on the format auto-detection in QEMU rather than
allowing the guest image file format to be specified. A privileged
guest user could potentially use this flaw to read arbitrary files on
the host that were accessible to a user on that host who was running a
program that utilized the libguestfs library. (CVE-2010-3851)

This erratum upgrades libguestfs to upstream version 1.7.17, which
includes a number of bug fixes and one enhancement. Documentation for
these bug fixes and this enhancement is provided in the Technical
Notes document, linked to in the References section.

All libguestfs users are advised to upgrade to these updated packages,
which correct this issue, and fix the bugs and add the enhancement
noted in the Technical Notes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-3851.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://docs.redhat.com/docs/en-US/Red_Hat_Enterprise_Linux/6/html/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0586.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:guestfish");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-java-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-mount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libguestfs-tools-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ocaml-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ocaml-libguestfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Sys-Guestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-libguestfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-libguestfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2011:0586";
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
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"guestfish-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libguestfs-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libguestfs-debuginfo-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libguestfs-devel-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libguestfs-java-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libguestfs-java-devel-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libguestfs-javadoc-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libguestfs-mount-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libguestfs-tools-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libguestfs-tools-c-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ocaml-libguestfs-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ocaml-libguestfs-devel-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"perl-Sys-Guestfs-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-libguestfs-1.7.17-17.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ruby-libguestfs-1.7.17-17.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "guestfish / libguestfs / libguestfs-debuginfo / libguestfs-devel / etc");
  }
}
