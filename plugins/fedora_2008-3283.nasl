#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-3283.
#

include("compat.inc");

if (description)
{
  script_id(32044);
  script_version ("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/21 22:13:39 $");

  script_cve_id("CVE-2008-1380");
  script_xref(name:"FEDORA", value:"2008-3283");

  script_name(english:"Fedora 8 : Miro-1.2-2.fc8 / chmsee-1.0.0-2.30.fc8 / devhelp-0.16.1-7.fc8 / epiphany-2.20.3-3.fc8 / etc (2008-3283)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox is an open source Web browser. A flaw was found in the
processing of malformed JavaScript content. A web page containing such
malicious content could cause Firefox to crash or, potentially,
execute arbitrary code as the user running Firefox. (CVE-2008-1380)
All Firefox users should upgrade to these updated packages, which
contain backported patches that correct these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=440518"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009506.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38f6a42a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009507.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3dadb1be"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009508.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb39538c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009509.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7dadc523"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009510.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6516fa7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009511.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64844c2a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009512.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5bd30fb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009513.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3a28dc9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009514.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c1479df7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009515.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6d219444"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009516.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8eba10d4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009517.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2cc15462"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009518.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9dbb9315"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78449226"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009527.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7954a68e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/25");
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
if (rpm_check(release:"FC8", reference:"Miro-1.2-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"chmsee-1.0.0-2.30.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"devhelp-0.16.1-7.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-2.20.3-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-extensions-2.20.1-7.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"firefox-2.0.0.14-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"galeon-2.0.4-2.fc8.3")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-python2-extras-2.19.1-14.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-web-photo-0.3-10.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gtkmozembedmm-1.4.2.cvs20060817-20.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kazehakase-0.5.4-2.fc8.1")) flag++;
if (rpm_check(release:"FC8", reference:"liferea-1.4.13-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"openvrml-0.17.5-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"ruby-gnome2-0.16.0-22.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"yelp-2.20.0-9.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / chmsee / devhelp / epiphany / epiphany-extensions / firefox / etc");
}
