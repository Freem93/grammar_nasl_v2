#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-6110.
#

include("compat.inc");

if (description)
{
  script_id(53817);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/20 22:05:54 $");

  script_osvdb_id(74744, 77506);
  script_xref(name:"FEDORA", value:"2011-6110");

  script_name(english:"Fedora 13 : widelands-0-0.24.build16.fc13 (2011-6110)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Rebase to new upstream release build16

    - Besides various enhancements this also fixes an
      arbitrary file overwrite vulnerability, which could be
      exploited when connecting to malicious servers for
      internet play!

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=684924"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-May/059611.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f32101f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected widelands package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:widelands");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC13", reference:"widelands-0-0.24.build16.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "widelands");
}
