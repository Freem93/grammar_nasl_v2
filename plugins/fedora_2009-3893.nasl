#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-3893.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(38160);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/08 20:21:55 $");

  script_cve_id("CVE-2009-0652", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312");
  script_xref(name:"FEDORA", value:"2009-3893");

  script_name(english:"Fedora 10 : Miro-2.0.3-3.fc10 / blam-1.8.5-9.fc10 / devhelp-0.22-7.fc10 / epiphany-2.24.3-5.fc10 / etc (2009-3893)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"http://www.mozilla.org/security/known-
vulnerabilities/firefox30.html#firefox3.0.9

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
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=486704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496252"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496262"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496263"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496266"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496267"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=496274"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022669.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dccb9213"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022670.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1da9ac9b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022671.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51fe0944"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022672.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f985006"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022673.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a89ae252"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022674.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e2adbb8c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022675.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac33e9d8"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022676.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?678d1f11"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022677.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7843c11a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022678.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a62512b4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022679.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec92897c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022680.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?03464481"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022681.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?44c2b183"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022682.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4d6567f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022683.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?731f7011"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022684.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32adc53e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022685.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4fb13176"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022686.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?897d9064"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022687.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1989b08b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 20, 79, 200, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/27");
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
if (rpm_check(release:"FC10", reference:"Miro-2.0.3-3.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-9.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"devhelp-0.22-7.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.3-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-extensions-2.24.0-7.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.9-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"galeon-2.0.7-9.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-7.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-29.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-17.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.5-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-4.fc10.1")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-9.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"perl-Gtk2-MozEmbed-0.08-5.fc10.2")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.18.1-5.fc10.1")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.9-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-8.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / devhelp / epiphany / epiphany-extensions / firefox / etc");
}
