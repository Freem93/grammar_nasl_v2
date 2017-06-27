#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0145. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31984);
  script_version ("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/03 17:16:32 $");

  script_cve_id("CVE-2007-1797", "CVE-2007-4985", "CVE-2007-4986", "CVE-2007-4988", "CVE-2008-1096", "CVE-2008-1097");
  script_bugtraq_id(23347, 25763, 28821, 28822);
  script_osvdb_id(43213);
  script_xref(name:"RHSA", value:"2008:0145");

  script_name(english:"RHEL 3 / 4 / 5 : ImageMagick (RHSA-2008:0145)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that correct several security issues are
now available for Red Hat Enterprise Linux versions 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

Several heap-based buffer overflow flaws were found in ImageMagick. If
a victim opened a specially crafted DCM or XWD file, an attacker could
potentially execute arbitrary code on the victim's machine.
(CVE-2007-1797)

Several denial of service flaws were found in ImageMagick's parsing of
XCF and DCM files. Attempting to process a specially crafted input
file in these formats could cause ImageMagick to enter an infinite
loop. (CVE-2007-4985)

Several integer overflow flaws were found in ImageMagick. If a victim
opened a specially crafted DCM, DIB, XBM, XCF or XWD file, an attacker
could potentially execute arbitrary code with the privileges of the
user running ImageMagick. (CVE-2007-4986)

An integer overflow flaw was found in ImageMagick's DIB parsing code.
If a victim opened a specially crafted DIB file, an attacker could
potentially execute arbitrary code with the privileges of the user
running ImageMagick. (CVE-2007-4988)

A heap-based buffer overflow flaw was found in the way ImageMagick
parsed XCF files. If a specially crafted XCF image was opened,
ImageMagick could be made to overwrite heap memory beyond the bounds
of its allocated memory. This could, potentially, allow an attacker to
execute arbitrary code on the machine running ImageMagick.
(CVE-2008-1096)

A heap-based buffer overflow flaw was found in ImageMagick's
processing of certain malformed PCX images. If a victim opened a
specially crafted PCX file, an attacker could possibly execute
arbitrary code on the victim's machine. (CVE-2008-1097)

All users of ImageMagick should upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-1797.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4985.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4986.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-4988.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2008-1097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2008-0145.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/18");
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
if (! ereg(pattern:"^(3|4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 3.x / 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2008:0145";
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
  if (rpm_check(release:"RHEL3", reference:"ImageMagick-5.5.6-28")) flag++;

  if (rpm_check(release:"RHEL3", reference:"ImageMagick-c++-5.5.6-28")) flag++;

  if (rpm_check(release:"RHEL3", reference:"ImageMagick-c++-devel-5.5.6-28")) flag++;

  if (rpm_check(release:"RHEL3", reference:"ImageMagick-devel-5.5.6-28")) flag++;

  if (rpm_check(release:"RHEL3", reference:"ImageMagick-perl-5.5.6-28")) flag++;


  if (rpm_check(release:"RHEL4", reference:"ImageMagick-6.0.7.1-17.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ImageMagick-c++-6.0.7.1-17.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ImageMagick-c++-devel-6.0.7.1-17.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ImageMagick-devel-6.0.7.1-17.el4_6.1")) flag++;

  if (rpm_check(release:"RHEL4", reference:"ImageMagick-perl-6.0.7.1-17.el4_6.1")) flag++;


  if (rpm_check(release:"RHEL5", reference:"ImageMagick-6.2.8.0-4.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"ImageMagick-c++-6.2.8.0-4.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"ImageMagick-c++-devel-6.2.8.0-4.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", reference:"ImageMagick-devel-6.2.8.0-4.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ImageMagick-perl-6.2.8.0-4.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ImageMagick-perl-6.2.8.0-4.el5_1.1")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ImageMagick-perl-6.2.8.0-4.el5_1.1")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
  }
}
