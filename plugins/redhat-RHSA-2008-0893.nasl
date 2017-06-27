#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0893. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34229);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/03 17:16:34 $");

  script_cve_id("CVE-2008-1372");
  script_osvdb_id(43425);
  script_xref(name:"RHSA", value:"2008:0893");

  script_name(english:"RHEL 2.1 / 3 / 4 / 5 : bzip2 (RHSA-2008:0893)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated bzip2 packages that fix a security issue are now available for
Red Hat Enterprise Linux 2.1, 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Bzip2 is a freely available, high-quality data compressor. It provides
both stand-alone compression and decompression utilities, as well as a
shared library for use with other programs.

A buffer over-read flaw was discovered in the bzip2 decompression
routine. This issue could cause an application linked against the
libbz2 library to crash when decompressing malformed archives.
(CVE-2008-1372)

Users of bzip2 should upgrade to these updated packages, which contain
a backported patch to resolve this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1372.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0893.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected bzip2, bzip2-devel and / or bzip2-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bzip2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bzip2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bzip2-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(2\.1|3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1 / 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0893";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bzip2-1.0.1-5.EL2.1")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bzip2-devel-1.0.1-5.EL2.1")) flag++;

  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"bzip2-libs-1.0.1-5.EL2.1")) flag++;


  if (rpm_check(release:"RHEL3", reference:"bzip2-1.0.2-12.EL3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bzip2-devel-1.0.2-12.EL3")) flag++;

  if (rpm_check(release:"RHEL3", reference:"bzip2-libs-1.0.2-12.EL3")) flag++;


  if (rpm_check(release:"RHEL4", reference:"bzip2-1.0.2-14.el4_7")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bzip2-devel-1.0.2-14.el4_7")) flag++;

  if (rpm_check(release:"RHEL4", reference:"bzip2-libs-1.0.2-14.el4_7")) flag++;


  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"bzip2-1.0.3-4.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"bzip2-1.0.3-4.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"bzip2-1.0.3-4.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bzip2-devel-1.0.3-4.el5_2")) flag++;

  if (rpm_check(release:"RHEL5", reference:"bzip2-libs-1.0.3-4.el5_2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bzip2 / bzip2-devel / bzip2-libs");
  }
}
