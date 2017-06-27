#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-10332.
#

include("compat.inc");

if (description)
{
  script_id(47719);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:16:08 $");

  script_cve_id("CVE-2010-1459");
  script_bugtraq_id(40351);
  script_xref(name:"FEDORA", value:"2010-10332");

  script_name(english:"Fedora 13 : gnome-sharp-2.24.1-1.fc13 / gtksourceview-sharp-2.0.12-11.fc13 / libgdiplus-2.6.4-1.fc13 / etc (2010-10332)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - update the mono stack to release 2.6.4

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=598155"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044047.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55461ebe"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044048.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?15b75f01"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044049.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ec80b03"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044050.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e856b116"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044052.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b52c25ed"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044054.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1750e472"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044055.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ff9dfa1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/044057.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc5ac0da"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-sharp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtksourceview-sharp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libgdiplus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mod_mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-basic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xsp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^13([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 13.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC13", reference:"gnome-sharp-2.24.1-1.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"gtksourceview-sharp-2.0.12-11.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"libgdiplus-2.6.4-1.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"mod_mono-2.6.3-1.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"mono-2.6.4-1.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"mono-basic-2.6.2-1.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"mono-tools-2.6.2-1.fc13")) flag++;
if (rpm_check(release:"FC13", reference:"xsp-2.6.4-1.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-sharp / gtksourceview-sharp / libgdiplus / mod_mono / mono / etc");
}
