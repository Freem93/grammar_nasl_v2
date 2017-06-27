#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-234.
#

include("compat.inc");

if (description)
{
  script_id(18316);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/10/21 21:38:04 $");

  script_cve_id("CVE-2005-0005");
  script_xref(name:"FEDORA", value:"2005-234");

  script_name(english:"Fedora Core 2 : ImageMagick-6.2.0.7-2.fc2 (2005-234)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andrei Nigmatulin discovered a heap based buffer overflow flaw in the
ImageMagick image handler. An attacker could create a carefully
crafted Photoshop Document (PSD) image in such a way that it would
cause ImageMagick to execute arbitrary code when processing the image.
The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2005-0005 to this issue.

A format string bug was found in the way ImageMagick handles
filenames. An attacker could execute arbitrary code in a victims
machine if they are able to trick the victim into opening a file with
a specially crafted name. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-0397 to this
issue.

A bug was found in the way ImageMagick handles TIFF tags. It is
possible that a TIFF image file with an invalid tag could cause
ImageMagick to crash.

A bug was found in ImageMagick's TIFF decoder. It is possible that a
specially crafted TIFF image file could cause ImageMagick to crash.

A bug was found in the way ImageMagick parses PSD files. It is
possible that a specially crafted PSD file could cause ImageMagick to
crash.

A heap overflow bug was found in ImageMagick's SGI parser. It is
possible that an attacker could execute arbitrary code by tricking a
user into opening a specially crafted SGI image file.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-March/000824.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7ba80458"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", cpu:"i386", reference:"ImageMagick-6.2.0.7-2.fc2")) flag++;
if (rpm_check(release:"FC2", reference:"ImageMagick-c++-6.2.0.7-2.fc2")) flag++;
if (rpm_check(release:"FC2", reference:"ImageMagick-c++-devel-6.2.0.7-2.fc2")) flag++;
if (rpm_check(release:"FC2", reference:"ImageMagick-debuginfo-6.2.0.7-2.fc2")) flag++;
if (rpm_check(release:"FC2", reference:"ImageMagick-devel-6.2.0.7-2.fc2")) flag++;
if (rpm_check(release:"FC2", reference:"ImageMagick-perl-6.2.0.7-2.fc2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
