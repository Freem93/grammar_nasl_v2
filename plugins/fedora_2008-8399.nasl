#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-8399.
#

include("compat.inc");

if (description)
{
  script_id(34306);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 22:23:17 $");

  script_xref(name:"FEDORA", value:"2008-8399");

  script_name(english:"Fedora 8 : Miro-1.2.3-4.fc8 / blam-1.8.3-18.fc8 / cairo-dock-1.6.2.3-1.fc8.1 / chmsee-1.0.0-4.31.fc8 / etc (2008-8399)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox is an open source Web browser. Several flaws were
found in the processing of malformed web content. A web page
containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code as the user running Firefox.
(CVE-2008-4058, CVE-2008-4060, CVE-2008-4061, CVE-2008-4062,
CVE-2008-4063, CVE-2008-4064) Several flaws were found in the way
malformed web content was displayed. A web page containing specially
crafted content could potentially trick a Firefox user into
surrendering sensitive information. (CVE-2008-4067, CVE-2008-4068) A
flaw was found in the way Firefox handles mouse click events. A web
page containing specially crafted JavaScript code could move the
content window while a mouse-button was pressed, causing any item
under the pointer to be dragged. This could, potentially, cause the
user to perform an unsafe drag-and-drop action. (CVE-2008-3837) A flaw
was found in Firefox that caused certain characters to be stripped
from JavaScript code. This flaw could allow malicious JavaScript to
bypass or evade script filters. (CVE-2008-4065) For technical details
regarding these flaws, please see the Mozilla security advisories for
Firefox 3.0.2.[1] All Firefox users should upgrade to these updated
packages, which contain patches that correct these issues. [1]
http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.2

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014892.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c516f095"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7982fe32"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014894.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7882e5a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014895.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4ca227c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014896.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6d89a51"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014897.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2071fd4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014898.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69a1905c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014899.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?988e68dc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014900.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ff0226d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014901.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c15e2d72"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014902.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44bb6340"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014903.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba4f29ef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014904.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?459d9fad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014905.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b8f4eb6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014906.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea5a052a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014907.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12a1556f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014908.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f361f20a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-September/014909.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47e9f8dd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cairo-dock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:evolution-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"Miro-1.2.3-4.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"blam-1.8.3-18.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"cairo-dock-1.6.2.3-1.fc8.1")) flag++;
if (rpm_check(release:"FC8", reference:"chmsee-1.0.0-4.31.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"devhelp-0.16.1-10.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-2.20.3-7.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-extensions-2.20.1-10.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"evolution-rss-0.0.8-12.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"firefox-2.0.0.17-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"galeon-2.0.4-5.fc8.3")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-python2-extras-2.19.1-17.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-web-photo-0.3-13.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gtkmozembedmm-1.4.2.cvs20060817-23.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kazehakase-0.5.5-1.fc8.1")) flag++;
if (rpm_check(release:"FC8", reference:"liferea-1.4.15-4.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"openvrml-0.17.8-2.0.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"ruby-gnome2-0.17.0-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"yelp-2.20.0-13.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / cairo-dock / chmsee / devhelp / epiphany / etc");
}
