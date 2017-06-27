#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-4083.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(38189);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/21 22:41:47 $");

  script_cve_id("CVE-2009-1313");
  script_bugtraq_id(34743);
  script_xref(name:"FEDORA", value:"2009-4083");

  script_name(english:"Fedora 10 : Miro-2.0.3-4.fc10 / blam-1.8.5-10.fc10 / devhelp-0.22-8.fc10 / epiphany-2.24.3-6.fc10 / etc (2009-4083)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to Firefox 3.0.10 fixing one security issue:
http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.10 Depending packages
rebuilt against new Firefox are also included in this update.
Additional bugs fixed in other packages: - totem: Fix YouTube plugin
following website changes

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=497447"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022881.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed30dc96"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022882.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef0486d3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022883.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?631065f3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022884.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?875d8523"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022885.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f036e1c5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022886.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e38f73a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022887.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c2cdfb8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022888.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57fadffb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022889.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43e7ac5d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022890.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ce980c8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022891.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bb2b4c01"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022892.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa9658ea"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8148632e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022894.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5dd61eff"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022895.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e769ba5e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022896.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?571b024a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022897.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?73074e6e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022898.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0a7562d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022899.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b4a290b1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC10", reference:"Miro-2.0.3-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-10.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"devhelp-0.22-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.3-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-extensions-2.24.0-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.10-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"galeon-2.0.7-10.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-30.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-18.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.5-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-4.fc10.2")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-10.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-9.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-9.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"perl-Gtk2-MozEmbed-0.08-6.fc10.1")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.18.1-5.fc10.2")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.10-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-9.fc10")) flag++;


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
