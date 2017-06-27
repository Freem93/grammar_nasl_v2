#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-11551.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(35233);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2008-5500", "CVE-2008-5503", "CVE-2008-5504", "CVE-2008-5506", "CVE-2008-5507", "CVE-2008-5508", "CVE-2008-5510", "CVE-2008-5511", "CVE-2008-5512", "CVE-2008-5513");
  script_bugtraq_id(32882);
  script_xref(name:"FEDORA", value:"2008-11551");

  script_name(english:"Fedora 8 : Miro-1.2.7-3.fc8 / blam-1.8.3-20.fc8 / cairo-dock-1.6.3.1-1.fc8.2 / chmsee-1.0.0-6.31.fc8 / etc (2008-11551)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to the new upstream Firefox release 2.0.0.19 fixing multiple
security issues: http://www.mozilla.org/security/known-
vulnerabilities/firefox20.html#firefox2.0.0.19 This update also
contains new builds of all applications depending on Gecko libraries,
built against the new version. Note: after the updated packages are
installed, Firefox must be restarted for the update to take effect.

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476273"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=476289"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018022.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dfe419ef"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018023.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?060d4ad1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d919ec1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96ec0c1b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018026.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a60e3c87"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018027.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69974726"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018028.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9588561b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018029.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?14b35b6a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018030.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d40bf06e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018031.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a4cf900f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018032.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e262a0f9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018033.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2d3070bc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?22f76c66"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018035.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67a8412f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018036.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8e4e1c6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018037.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?792657bd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-December/018039.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b129a38e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 79, 200, 264, 399);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/21");
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
if (rpm_check(release:"FC8", reference:"Miro-1.2.7-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"blam-1.8.3-20.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"cairo-dock-1.6.3.1-1.fc8.2")) flag++;
if (rpm_check(release:"FC8", reference:"chmsee-1.0.0-6.31.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"devhelp-0.16.1-12.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-2.20.3-9.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-extensions-2.20.1-12.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"evolution-rss-0.0.8-14.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"firefox-2.0.0.19-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"galeon-2.0.4-7.fc8.3")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-python2-extras-2.19.1-20.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-web-photo-0.3-15.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kazehakase-0.5.6-1.fc8.2")) flag++;
if (rpm_check(release:"FC8", reference:"liferea-1.4.15-6.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"openvrml-0.17.10-3.0.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"ruby-gnome2-0.17.0-4.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"yelp-2.20.0-15.fc8")) flag++;


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
