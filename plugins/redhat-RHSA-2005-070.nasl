#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:070. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17621);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/28 17:55:17 $");

  script_cve_id("CVE-2005-0005", "CVE-2005-0397", "CVE-2005-0759", "CVE-2005-0760", "CVE-2005-0761", "CVE-2005-0762");
  script_bugtraq_id(12873, 12874, 12875, 12876, 13705);
  script_osvdb_id(13028, 14372, 15111, 15112, 15113, 15114);
  script_xref(name:"RHSA", value:"2005:070");

  script_name(english:"RHEL 2.1 / 3 : ImageMagick (RHSA-2005:070)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ImageMagick packages that fix a heap based buffer overflow are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

ImageMagick is an image display and manipulation tool for the X Window
System.

Andrei Nigmatulin discovered a heap based buffer overflow flaw in the
ImageMagick image handler. An attacker could create a carefully
crafted Photoshop Document (PSD) image in such a way that it would
cause ImageMagick to execute arbitrary code when processing the image.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0005 to this issue.

A format string bug was found in the way ImageMagick handles
filenames. An attacker could execute arbitrary code on a victim's
machine if they were able to trick the victim into opening a file with
a specially crafted name. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0397 to this
issue.

A bug was found in the way ImageMagick handles TIFF tags. It is
possible that a TIFF image file with an invalid tag could cause
ImageMagick to crash. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0759 to this issue.

A bug was found in ImageMagick's TIFF decoder. It is possible that a
specially crafted TIFF image file could cause ImageMagick to crash.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0760 to this issue.

A bug was found in the way ImageMagick parses PSD files. It is
possible that a specially crafted PSD file could cause ImageMagick to
crash. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-0761 to this issue.

A heap overflow bug was found in ImageMagick's SGI parser. It is
possible that an attacker could execute arbitrary code by tricking a
user into opening a specially crafted SGI image file. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0762 to this issue.

Users of ImageMagick should upgrade to these updated packages, which
contain backported patches, and are not vulnerable to these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0397.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0759.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0760.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0761.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2005-0762.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2005-070.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2005:070";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ImageMagick-5.3.8-10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ImageMagick-c++-5.3.8-10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ImageMagick-c++-devel-5.3.8-10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ImageMagick-devel-5.3.8-10")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"ImageMagick-perl-5.3.8-10")) flag++;

  if (rpm_check(release:"RHEL3", reference:"ImageMagick-5.5.6-13")) flag++;
  if (rpm_check(release:"RHEL3", reference:"ImageMagick-c++-5.5.6-13")) flag++;
  if (rpm_check(release:"RHEL3", reference:"ImageMagick-c++-devel-5.5.6-13")) flag++;
  if (rpm_check(release:"RHEL3", reference:"ImageMagick-devel-5.5.6-13")) flag++;
  if (rpm_check(release:"RHEL3", reference:"ImageMagick-perl-5.5.6-13")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
  }
}
