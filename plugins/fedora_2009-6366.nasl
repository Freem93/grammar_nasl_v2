#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-6366.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(39403);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/08 20:21:55 $");

  script_cve_id("CVE-2009-1392", "CVE-2009-1832", "CVE-2009-1833", "CVE-2009-1834", "CVE-2009-1835", "CVE-2009-1836", "CVE-2009-1837", "CVE-2009-1838", "CVE-2009-1839", "CVE-2009-1840", "CVE-2009-1841");
  script_bugtraq_id(35360, 35370, 35371, 35372, 35373, 35377, 35380, 35383, 35386);
  script_xref(name:"FEDORA", value:"2009-6366");

  script_name(english:"Fedora 10 : Miro-2.0.3-5.fc10 / blam-1.8.5-11.fc10 / devhelp-0.22-9.fc10 / epiphany-2.24.3-7.fc10 / etc (2009-6366)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to new upstream Firefox version 3.0.11, fixing multiple
security issues detailed in the upstream advisories:
http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.11 Update also includes all
packages depending on gecko-libs rebuild against new version of
Firefox / XULRunner.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/known-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503569"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503573"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503579"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503580"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503581"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503582"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=503583"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024950.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0f7e17ad"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024951.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b721524d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024952.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe8a5972"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024953.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a618dce6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024954.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0b678ea"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024955.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?386d572b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024956.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc3370d8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024957.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d4cb9e9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024958.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4283210"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024959.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5b0178e7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024960.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95553e2b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024961.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?336cd986"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024962.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e33772e3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024963.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfadd14a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024964.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2c81bff"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024965.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c5a7e2bf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024966.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ee0fca0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024967.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f28dc9ba"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-June/024968.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96265835"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 94, 200, 264, 287, 362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gecko-sharp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:google-gadgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mugshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pcmanx-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Gtk2-MozEmbed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^10([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 10.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC10", reference:"Miro-2.0.3-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-11.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"devhelp-0.22-9.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.3-7.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-extensions-2.24.3-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.11-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"galeon-2.0.7-11.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-9.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-31.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-19.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.5-7.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-4.fc10.3")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-11.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-10.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-10.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"perl-Gtk2-MozEmbed-0.08-6.fc10.2")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.18.1-5.fc10.3")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.11-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-10.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / devhelp / epiphany / epiphany-extensions / firefox / etc");
}
