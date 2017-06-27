#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-3249.
#

include("compat.inc");

if (description)
{
  script_id(32040);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:13:39 $");

  script_cve_id("CVE-2008-1380");
  script_xref(name:"FEDORA", value:"2008-3249");

  script_name(english:"Fedora 7 : Miro-1.2-2.fc7 / chmsee-1.0.0-2.30.fc7 / devhelp-0.13-16.fc7 / epiphany-2.18.3-9.fc7 / etc (2008-3249)");
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009457.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d4e82e6b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009458.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13585eba"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009459.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98adf529"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009460.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52a497d4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009461.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e07fc0fd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009462.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?841485e3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009463.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7a1b61c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009464.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1afb8e4b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009465.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fcfb72e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009466.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28f7ed17"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009467.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?307acf90"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b3859c93"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009469.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90311d77"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-April/009470.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?106e8c81"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"Miro-1.2-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"chmsee-1.0.0-2.30.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"devhelp-0.13-16.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-2.18.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-extensions-2.18.3-9")) flag++;
if (rpm_check(release:"FC7", reference:"firefox-2.0.0.14-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"galeon-2.0.3-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gnome-python2-extras-2.14.3-10.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gtkmozembedmm-1.4.2.cvs20060817-17.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kazehakase-0.5.4-2.fc7.2")) flag++;
if (rpm_check(release:"FC7", reference:"liferea-1.4.13-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-0.16.7-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnome2-0.16.0-23.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"yelp-2.18.1-11.fc7")) flag++;


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
