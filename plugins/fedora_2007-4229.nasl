#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-4229.
#

include("compat.inc");

if (description)
{
  script_id(29277);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:04:01 $");

  script_cve_id("CVE-2007-6183");
  script_bugtraq_id(26616);
  script_xref(name:"FEDORA", value:"2007-4229");

  script_name(english:"Fedora 7 : ruby-gnome2-0.16.0-18.fc7 (2007-4229)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fix CVE-2007-6183, format string vulnerability

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=402871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=405591"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-December/005713.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e9dbca1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-atk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-atk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gconf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gdkpixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-glib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-glib2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnomecanvas2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnomeprint2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnomeprintui2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gtk2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gtkglext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gtksourceview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-libart2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-libart2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-libglade2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-panelapplet2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-pango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-pango-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-rsvg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-vte");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"ruby-atk-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-atk-devel-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gconf2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gdkpixbuf2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-glib2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-glib2-devel-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnome2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnome2-debuginfo-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnomecanvas2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnomeprint2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnomeprintui2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnomevfs-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtk2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtk2-devel-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtkglext-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtkhtml2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtkmozembed-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtksourceview-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-libart2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-libart2-devel-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-libglade2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-panelapplet2-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-pango-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-pango-devel-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-poppler-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-rsvg-0.16.0-18.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-vte-0.16.0-18.fc7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ruby-atk / ruby-atk-devel / ruby-gconf2 / ruby-gdkpixbuf2 / etc");
}
