#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-1085.
#

include("compat.inc");

if (description)
{
  script_id(20229);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 21:09:32 $");

  script_cve_id("CVE-2005-3186");
  script_xref(name:"FEDORA", value:"2005-1085");

  script_name(english:"Fedora Core 4 : gdk-pixbuf-0.22.0-18.fc4.2 (2005-1085)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The gdk-pixbuf package contains an image loading library used with the
GNOME GUI desktop environment.

A bug was found in the way gdk-pixbuf processes XPM images. An
attacker could create a carefully crafted XPM file in such a way that
it could cause an application linked with gdk-pixbuf to execute
arbitrary code when the file was opened by a victim. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-3186 to this issue.

Ludwig Nussel discovered an integer overflow bug in the way gdk-pixbuf
processes XPM images. An attacker could create a carefully crafted XPM
file in such a way that it could cause an application linked with
gdk-pixbuf to execute arbitrary code or crash when the file was opened
by a victim. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2005-2976 to this issue.

Ludwig Nussel also discovered an infinite-loop denial of service bug
in the way gdk-pixbuf processes XPM images. An attacker could create a
carefully crafted XPM file in such a way that it could cause an
application linked with gdk-pixbuf to stop responding when the file
was opened by a victim. The Common Vulnerabilities and Exposures
project has assigned the name CVE-2005-2975 to this issue.

Users of gdk-pixbuf are advised to upgrade to these updated packages,
which contain backported patches and are not vulnerable to these
issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-November/001581.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4518078"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gdk-pixbuf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gdk-pixbuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gdk-pixbuf-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/21");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"gdk-pixbuf-0.22.0-18.fc4.2")) flag++;
if (rpm_check(release:"FC4", reference:"gdk-pixbuf-debuginfo-0.22.0-18.fc4.2")) flag++;
if (rpm_check(release:"FC4", reference:"gdk-pixbuf-devel-0.22.0-18.fc4.2")) flag++;
if (rpm_check(release:"FC4", reference:"gdk-pixbuf-gnome-0.22.0-18.fc4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdk-pixbuf / gdk-pixbuf-debuginfo / gdk-pixbuf-devel / etc");
}
