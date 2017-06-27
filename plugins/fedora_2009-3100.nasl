#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-3100.
#

include("compat.inc");

if (description)
{
  script_id(37824);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/10/21 22:41:47 $");

  script_cve_id("CVE-2009-1044", "CVE-2009-1169");
  script_bugtraq_id(34181, 34235);
  script_xref(name:"FEDORA", value:"2009-3100");

  script_name(english:"Fedora 10 : Miro-2.0.3-2.fc10 / blam-1.8.5-8.fc10 / devhelp-0.22-6.fc10 / epiphany-2.24.3-4.fc10 / etc (2009-3100)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A memory corruption flaw was discovered in the way Firefox handles XML
files containing an XSLT transform. A remote attacker could use this
flaw to crash Firefox or, potentially, execute arbitrary code as the
user running Firefox. (CVE-2009-1169) A flaw was discovered in the way
Firefox handles certain XUL garbage collection events. A remote
attacker could use this flaw to crash Firefox or, potentially, execute
arbitrary code as the user running Firefox. (CVE-2009-1044)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e27367e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021835.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c2e4e00"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021836.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ead787e6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021837.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82fb14d4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0a8ab71"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021839.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8b93ce0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021840.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?527bdd4d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021841.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?317c4055"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39045ac3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021843.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?042bfeb9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021844.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1b6b5508"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021845.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ac5c0a7c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021846.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5be312ab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021847.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c03fa684"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021848.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?49be5a5b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021849.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d73b1b01"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021850.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef8d768d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021851.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?388377f6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021852.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?288b32e8"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:evolution-rss");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
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
if (rpm_check(release:"FC10", reference:"Miro-2.0.3-2.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"blam-1.8.5-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"devhelp-0.22-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-2.24.3-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"epiphany-extensions-2.24.0-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"evolution-rss-0.1.2-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"firefox-3.0.8-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"galeon-2.0.7-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gecko-sharp2-0.13-6.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-python2-extras-2.19.1-28.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"gnome-web-photo-0.3-16.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"google-gadgets-0.10.5-4.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"kazehakase-0.5.6-1.fc10.5")) flag++;
if (rpm_check(release:"FC10", reference:"mozvoikko-0.9.5-8.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"mugshot-1.2.2-7.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"pcmanx-gtk2-0.3.8-7.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"ruby-gnome2-0.18.1-5.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"xulrunner-1.9.0.8-1.fc10")) flag++;
if (rpm_check(release:"FC10", reference:"yelp-2.24.0-7.fc10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / devhelp / epiphany / epiphany-extensions / etc");
}
