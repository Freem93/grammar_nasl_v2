#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-9669.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(34778);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:21:54 $");

  script_cve_id("CVE-2008-0017", "CVE-2008-4582", "CVE-2008-5014", "CVE-2008-5015", "CVE-2008-5016", "CVE-2008-5017", "CVE-2008-5018", "CVE-2008-5019", "CVE-2008-5021", "CVE-2008-5022", "CVE-2008-5023", "CVE-2008-5024");
  script_xref(name:"FEDORA", value:"2008-9669");

  script_name(english:"Fedora 9 : Miro-1.2.7-2.fc9 / cairo-dock-1.6.3.1-1.fc9.1 / chmsee-1.0.1-6.fc9 / devhelp-0.19.1-6.fc9 / etc (2008-9669)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox and xulrunner packages that fix various security
issues are now available for Fedora Core 9. This update has been rated
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
security advisories for Firefox 3.0.4[1]. All firefox users and users
of packages depending on xulrunner[2] should upgrade to these updated
packages, which contain patches that correct these issues. [1]
http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.4 [2] cairo-dock chmsee
devhelp epiphany epiphany-extensions evolution-rss galeon
gnome-python2-extras gnome- web-photo google-gadgets gtkmozembedmm
kazehakase Miro mozvoikko mugshot ruby- gnome2 totem yelp Provides
Python bindings for libgdl on PPC64. This update fixes a build break.

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470873"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=470876"
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016252.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8075280"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016253.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fa23fca"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016254.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b128c08f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016255.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51682c95"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016256.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3cdac40"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016257.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d1e7150"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016258.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ac830d0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016259.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?84a7006c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016260.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26d313e9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7310946f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016262.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2a88a65"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016263.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d1573ff"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016264.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63be9ff8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016265.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29e7e1a1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016266.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2c2f70c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016267.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41430d17"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016268.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63261f01"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016269.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a9a1067"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016270.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8bf60bf"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016271.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cb2f896"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016272.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d5534a2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 94, 119, 189, 264, 287, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:google-gadgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mugshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"Miro-1.2.7-2.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"cairo-dock-1.6.3.1-1.fc9.1")) flag++;
if (rpm_check(release:"FC9", reference:"chmsee-1.0.1-6.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"devhelp-0.19.1-6.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-2.22.2-5.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-extensions-2.22.1-5.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"evolution-rss-0.1.0-4.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"firefox-3.0.4-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"galeon-2.0.7-3.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-python2-extras-2.19.1-21.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-web-photo-0.3-15.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"google-gadgets-0.10.1-5.fc9.1")) flag++;
if (rpm_check(release:"FC9", reference:"gtkmozembedmm-1.4.2.cvs20060817-22.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"kazehakase-0.5.6-1.fc9.1")) flag++;
if (rpm_check(release:"FC9", reference:"mozvoikko-0.9.5-4.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"mugshot-1.2.2-3.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"ruby-gnome2-0.17.0-3.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"seamonkey-1.1.13-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"totem-2.23.2-8.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"xulrunner-1.9.0.4-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"yelp-2.22.1-6.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / cairo-dock / chmsee / devhelp / epiphany / etc");
}
