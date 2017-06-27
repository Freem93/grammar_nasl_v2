#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-1033.
#

include("compat.inc");

if (description)
{
  script_id(20101);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 21:09:32 $");

  script_xref(name:"FEDORA", value:"2005-1033");

  script_name(english:"Fedora Core 4 : gdb-6.3.0.0-1.84 (2005-1033)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is an fc4 update for gdb that includes security issues :

CVE-2005-1704 Integer Overflow in gdb

This problem is that gdb's internal copy of bfd does not protect
against heap-based overflow.

CVE-2005-1705 gdb arbitrary command execution

This problem allows unprotected .gdbinit files to execute arbitrary
commands during gdb startup.

Fixes for both problems are found in :

gdb-6.3.0.0-1.84

This release also contains some additional fixes from the last update.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-October/001522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55e6a187"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdb and / or gdb-debuginfo packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"gdb-6.3.0.0-1.84")) flag++;
if (rpm_check(release:"FC4", reference:"gdb-debuginfo-6.3.0.0-1.84")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gdb / gdb-debuginfo");
}
