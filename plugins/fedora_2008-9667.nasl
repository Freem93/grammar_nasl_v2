#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-9667.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(34777);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2008-0017", "CVE-2008-4582", "CVE-2008-5012", "CVE-2008-5013", "CVE-2008-5014", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024");
  script_xref(name:"FEDORA", value:"2008-9667");

  script_name(english:"Fedora 8 : Miro-1.2.7-2.fc8 / blam-1.8.3-19.fc8 / cairo-dock-1.6.3.1-1.fc8.1 / chmsee-1.0.0-5.31.fc8 / etc (2008-9667)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox and xulrunner packages that fix various security
issues are now available for Fedora Core 8. This update has been rated
as having critical security impact by the Fedora Security Response
Team. Mozilla Firefox is an open source Web browser. Several flaws
were found in the processing of malformed web content. A web page
containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code as the user running Firefox.
(CVE-2008-0017, CVE-2008-5014, CVE-2008-5016, CVE-2008-5017,
CVE-2008-5018, CVE-2008-5019, CVE-2008-5021) Several flaws were found
in the way malformed content was processed. A website containing
specially crafted content could potentially trick a Firefox user into
surrendering sensitive information. (CVE-2008-5022, CVE-2008-5023,
CVE-2008-5024) A flaw was found in the way Firefox opened 'file:'
URIs. If a file: URI was loaded in the same tab as a chrome or
privileged 'about:' page, the file: URI could execute arbitrary code
with the permissions of the user running Firefox. (CVE-2008-5015) For
technical details regarding these flaws, please see the Mozilla
security advisories for Firefox 2.0.0.18[1]. All firefox users and
users of packages depending on firefox[2] should upgrade to these
updated packages, which correct these issues. [1]
http://www.mozilla.org/security/known-
vulnerabilities/firefox20.html#firefox2.0.0.18 [2] blam cairo-dock
chmsee devhelp epiphany epiphany-extensions evolution-rss galeon
gnome-python2-extras gnome-web-photo kazehakase liferea Miro openvrml
ruby-gnome2 yelp Provides Python bindings for libgdl on PPC64.

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470864"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470883"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470884"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470894"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470895"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470903"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016233.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6db5d30"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?600d585c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016235.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb0cedcf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016236.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3c058f8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016237.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?560b7225"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016238.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe591968"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016239.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08b920c6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016240.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99c0fa87"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016241.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?397ca14f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b7d4200"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016243.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdf6f7b1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016244.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?198521cc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016245.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2c57566b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016246.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c66e2091"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17fdc2f6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016248.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8ff66be1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec2d94d0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016250.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2392f2c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 94, 119, 189, 200, 264, 287, 399);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC8", reference:"Miro-1.2.7-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"blam-1.8.3-19.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"cairo-dock-1.6.3.1-1.fc8.1")) flag++;
if (rpm_check(release:"FC8", reference:"chmsee-1.0.0-5.31.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"devhelp-0.16.1-11.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-2.20.3-8.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-extensions-2.20.1-11.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"evolution-rss-0.0.8-13.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"firefox-2.0.0.18-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"galeon-2.0.4-6.fc8.3")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-python2-extras-2.19.1-19.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-web-photo-0.3-14.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kazehakase-0.5.6-1.fc8.1")) flag++;
if (rpm_check(release:"FC8", reference:"liferea-1.4.15-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"openvrml-0.17.10-2.0.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"ruby-gnome2-0.17.0-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"seamonkey-1.1.13-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"yelp-2.20.0-14.fc8")) flag++;


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
