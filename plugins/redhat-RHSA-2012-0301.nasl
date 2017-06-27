#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0301. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58055);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2010-4167");
  script_bugtraq_id(45044);
  script_osvdb_id(69445);
  script_xref(name:"RHSA", value:"2012:0301");

  script_name(english:"RHEL 5 : ImageMagick (RHSA-2012:0301)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that fix one security issue and multiple
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

It was found that ImageMagick utilities tried to load ImageMagick
configuration files from the current working directory. If a user ran
an ImageMagick utility in an attacker-controlled directory containing
a specially crafted ImageMagick configuration file, it could cause the
utility to execute arbitrary code. (CVE-2010-4167)

This update also fixes the following bugs :

* Previously, the 'identify -verbose' command failed with an assertion
if there was no image information available. An upstream patch has
been applied, so that GetImageOption() is now called correctly. Now,
the 'identify -verbose' command works correctly even if no image
information is available. (BZ#502626)

* Previously, an incorrect use of the semaphore data type led to a
deadlock. As a consequence, the ImageMagick utility could become
unresponsive when converting JPEG files to PDF (Portable Document
Format) files. A patch has been applied to address the deadlock issue,
and JPEG files can now be properly converted to PDF files. (BZ#530592)

* Previously, running the 'convert' command with the '-color' option
failed with a memory allocation error. The source code has been
modified to fix problems with memory allocation. Now, using the
'convert' command with the '-color' option works correctly.
(BZ#616538)

* Previously, ImageMagick could become unresponsive when using the
'display' command on damaged GIF files. The source code has been
revised to prevent the issue. ImageMagick now produces an error
message in the described scenario. A file selector is now opened so
the user can choose another image to display. (BZ#693989)

* Prior to this update, the 'convert' command did not handle rotated
PDF files correctly. As a consequence, the output was rendered as a
portrait with the content being cropped. With this update, the PDF
render geometry is modified, and the output produced by the 'convert'
command is properly rendered as a landscape. (BZ#694922)

All users of ImageMagick are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
All running instances of ImageMagick must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4167.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0301.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0301";
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
  if (rpm_check(release:"RHEL5", reference:"ImageMagick-6.2.8.0-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ImageMagick-c++-6.2.8.0-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ImageMagick-c++-devel-6.2.8.0-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ImageMagick-debuginfo-6.2.8.0-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"ImageMagick-devel-6.2.8.0-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ImageMagick-perl-6.2.8.0-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ImageMagick-perl-6.2.8.0-12.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ImageMagick-perl-6.2.8.0-12.el5")) flag++;

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
