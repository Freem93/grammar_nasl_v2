#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-3875.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(37309);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/08 20:21:55 $");

  script_cve_id("CVE-2009-0652", "CVE-2009-1302", "CVE-2009-1303", "CVE-2009-1304", "CVE-2009-1305", "CVE-2009-1306", "CVE-2009-1307", "CVE-2009-1308", "CVE-2009-1309", "CVE-2009-1310", "CVE-2009-1311", "CVE-2009-1312");
  script_xref(name:"FEDORA", value:"2009-3875");

  script_name(english:"Fedora 9 : Miro-2.0.3-3.fc9 / blam-1.8.5-8.fc9.1 / chmsee-1.0.1-11.fc9 / devhelp-0.19.1-11.fc9 / etc (2009-3875)");
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022628.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9aa2b83d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022629.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6aaaa992"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022630.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57ba0cab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022631.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c452f848"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed2bc550"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022633.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?de5ae17b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022634.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9160c89c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022635.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5a5e1487"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022636.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c51bc107"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022637.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5294cc4d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022638.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76e1bd03"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022639.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?746611a6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022640.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce5dd47a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022641.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?59a05df6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022642.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ee681e20"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022643.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1979407f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022644.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30f035ab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022645.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20bd9531"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022646.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2e57fc3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-April/022647.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95acaffc"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"Miro-2.0.3-3.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"blam-1.8.5-8.fc9.1")) flag++;
if (rpm_check(release:"FC9", reference:"chmsee-1.0.1-11.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"devhelp-0.19.1-11.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-2.22.2-10.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-extensions-2.22.1-10.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"evolution-rss-0.1.0-10.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"firefox-3.0.9-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"galeon-2.0.7-9.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-python2-extras-2.19.1-26.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-web-photo-0.3-20.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"google-gadgets-0.10.5-5.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gtkmozembedmm-1.4.2.cvs20060817-28.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"kazehakase-0.5.6-4.fc9.1")) flag++;
if (rpm_check(release:"FC9", reference:"mozvoikko-0.9.5-9.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"mugshot-1.2.2-8.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"ruby-gnome2-0.17.0-8.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"totem-2.23.2-14.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"xulrunner-1.9.0.9-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"yelp-2.22.1-11.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / chmsee / devhelp / epiphany / epiphany-extensions / etc");
}
