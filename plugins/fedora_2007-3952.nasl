#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-3952.
#

include("compat.inc");

if (description)
{
  script_id(28345);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:11:35 $");

  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
  script_bugtraq_id(26385, 26589, 26593);
  script_xref(name:"FEDORA", value:"2007-3952");

  script_name(english:"Fedora 7 : Miro-1.0-2.fc7 / blam-1.8.3-10.fc7 / chmsee-1.0.0-1.27.fc7 / devhelp-0.13-12.fc7 / etc (2007-3952)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Fedora 7.

This update has been rated as having critical security impact by the
Fedora Security Response Team.

Mozilla Firefox is an open source Web browser.

A cross-site scripting flaw was found in the way Firefox handled the
jar: URI scheme. It was possible for a malicious website to leverage
this flaw and conduct a cross-site scripting attack against a user
running Firefox. (CVE-2007-5947)

Several flaws were found in the way Firefox processed certain
malformed web content. A web page containing malicious content could
cause Firefox to crash, or potentially execute arbitrary code as the
user running Firefox. (CVE-2007-5959)

A race condition existed when Firefox set the 'window.location'
property for a web page. This flaw could allow a web page to set an
arbitrary Referer header, which may lead to a Cross-site Request
Forgery (CSRF) attack against websites that rely only on the Referer
header for protection. (CVE-2007-5960)

Users of Firefox are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005411.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f4e38da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?391a9f25"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?db401f4f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f3f7b4d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005415.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ffece71"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005416.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?12393ef3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005417.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0af9fb9c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8360769"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005419.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b7e7175"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005420.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aadc3c9e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005421.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28660866"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005422.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?237b9220"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005423.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?914cc116"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005424.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f4ca37d7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/005425.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?766f2f9d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-gtkhtml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-gtkmozembed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-gtkspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-libegg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase-hyperestraier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:liferea-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml-gl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml-mozilla-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml-xembed");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/29");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"Miro-1.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"Miro-debuginfo-1.0-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"blam-1.8.3-10.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"blam-debuginfo-1.8.3-10.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"chmsee-1.0.0-1.27.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"chmsee-debuginfo-1.0.0-1.27.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"devhelp-0.13-12.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"devhelp-debuginfo-0.13-12.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"devhelp-devel-0.13-12.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-2.18.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-debuginfo-2.18.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-devel-2.18.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-extensions-2.18.3-6")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-extensions-debuginfo-2.18.3-6")) flag++;
if (rpm_check(release:"FC7", reference:"firefox-2.0.0.10-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"firefox-debuginfo-2.0.0.10-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"firefox-devel-2.0.0.10-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"galeon-2.0.3-14.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"galeon-debuginfo-2.0.3-14.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gnome-python2-extras-2.14.3-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gnome-python2-extras-debuginfo-2.14.3-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gnome-python2-gtkhtml2-2.14.3-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gnome-python2-gtkmozembed-2.14.3-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gnome-python2-gtkspell-2.14.3-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gnome-python2-libegg-2.14.3-7.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gtkmozembedmm-1.4.2.cvs20060817-14.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gtkmozembedmm-debuginfo-1.4.2.cvs20060817-14.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gtkmozembedmm-devel-1.4.2.cvs20060817-14.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kazehakase-0.5.0-1.fc7.2")) flag++;
if (rpm_check(release:"FC7", reference:"kazehakase-debuginfo-0.5.0-1.fc7.2")) flag++;
if (rpm_check(release:"FC7", reference:"kazehakase-hyperestraier-0.5.0-1.fc7.2")) flag++;
if (rpm_check(release:"FC7", reference:"kazehakase-ruby-0.5.0-1.fc7.2")) flag++;
if (rpm_check(release:"FC7", reference:"liferea-1.4.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"liferea-debuginfo-1.4.8-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-0.16.7-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-debuginfo-0.16.7-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-devel-0.16.7-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-gl-0.16.7-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-gl-devel-0.16.7-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-mozilla-plugin-0.16.7-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-player-0.16.7-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-xembed-0.16.7-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-atk-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-atk-devel-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gconf2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gdkpixbuf2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-glib2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-glib2-devel-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnome2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnome2-debuginfo-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnomecanvas2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnomeprint2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnomeprintui2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnomevfs-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtk2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtk2-devel-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtkglext-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtkhtml2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtkmozembed-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gtksourceview-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-libart2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-libart2-devel-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-libglade2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-panelapplet2-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-pango-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-pango-devel-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-poppler-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-rsvg-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-vte-0.16.0-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"yelp-2.18.1-8.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"yelp-debuginfo-2.18.1-8.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / Miro-debuginfo / blam / blam-debuginfo / chmsee / etc");
}
