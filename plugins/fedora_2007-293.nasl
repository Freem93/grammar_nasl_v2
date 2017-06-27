#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-293.
#

include("compat.inc");

if (description)
{
  script_id(24729);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0775", "CVE-2007-0776", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0995", "CVE-2007-0996");
  script_xref(name:"FEDORA", value:"2007-293");

  script_name(english:"Fedora Core 6 : devhelp-0.12-10.fc6 / epiphany-2.16.3-2.fc6 / firefox-1.5.0.10-1.fc6 / etc (2007-293)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Fedora Core host is missing one or more security updates :

epiphany-2.16.3-2.fc6 :

  - Mon Feb 26 2007 Martin Stransky <stransky at redhat.com>
    - 2.16.3-2

    - Rebuild against newer gecko

devhelp-0.12-10.fc6 :

  - Mon Feb 26 2007 Martin Stransky <stransky at redhat.com>
    - 0.12.6-10

    - Rebuild against newer gecko

yelp-2.16.0-12.fc6 :

  - Mon Feb 26 2007 Martin Stransky <stransky at redhat.com>
    - 2.16.0-12

    - Rebuild against newer gecko

firefox-1.5.0.10-1.fc6 :

  - Mon Feb 26 2007 - 1.5.0.10-1.fc6

    - Rebuild against firefox-1.5.0.10.

gnome-python2-extras-2.14.2-9.fc6 :

  - Mon Feb 26 2007 Matthew Barnes <mbarnes at redhat.com> -
    2.14.2-9.fc6

    - Rebuild against firefox-1.5.0.10.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001517.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?890f4065"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001518.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac2d44c4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?125c2932"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001520.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7e42849e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-February/001521.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?327e8f1b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(79, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-gtkspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-libegg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"devhelp-0.12-10.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"devhelp-debuginfo-0.12-10.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"devhelp-devel-0.12-10.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"epiphany-2.16.3-2.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"epiphany-debuginfo-2.16.3-2.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"epiphany-devel-2.16.3-2.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"firefox-1.5.0.10-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"firefox-debuginfo-1.5.0.10-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"firefox-devel-1.5.0.10-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"gnome-python2-extras-2.14.2-9.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"gnome-python2-extras-debuginfo-2.14.2-9.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"gnome-python2-gtkhtml2-2.14.2-9.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"gnome-python2-gtkmozembed-2.14.2-9.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"gnome-python2-gtkspell-2.14.2-9.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"gnome-python2-libegg-2.14.2-9.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"yelp-2.16.0-12.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"yelp-debuginfo-2.16.0-12.fc6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-debuginfo / devhelp-devel / epiphany / etc");
}
