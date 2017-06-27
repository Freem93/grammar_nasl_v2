#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-13523.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(69085);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/10/19 21:12:41 $");

  script_cve_id("CVE-2013-1569", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2419");
  script_bugtraq_id(59131, 59166, 59179, 59190);
  script_xref(name:"FEDORA", value:"2013-13523");

  script_name(english:"Fedora 19 : fontmatrix-0.9.99-12.r1218.fc19 / icu-50.1.2-7.fc19 / libreoffice-4.1.0.3-2.fc19 / etc (2013-13523)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is an update for icu. Unfortunately, one of the fixes adds a new
virtual function to LayoutEngine class, breaking ABI. So dependent
packages have to be updated too.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=952656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=952708"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=952709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=952711"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112689.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e4aa87e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112690.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?522bd8b6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112691.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7c8b3f4b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112692.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9b3ff77e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/112693.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15bf25ec"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:fontmatrix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:icu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openttd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pyicu");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"fontmatrix-0.9.99-12.r1218.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"icu-50.1.2-7.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"libreoffice-4.1.0.3-2.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"openttd-1.3.2-0.2.RC1.fc19")) flag++;
if (rpm_check(release:"FC19", reference:"pyicu-1.5-2.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "fontmatrix / icu / libreoffice / openttd / pyicu");
}
