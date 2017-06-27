#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-12242.
#

include("compat.inc");

if (description)
{
  script_id(78252);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 22:06:08 $");

  script_xref(name:"FEDORA", value:"2014-12242");

  script_name(english:"Fedora 20 : mksh-50c-1.fc20 (2014-12242)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"R50c is a security fix release :

  - Know more rare signals when generating sys_signame[]
    replacement

    - OpenBSD sync (mostly RCSID only)

    - Document HISTSIZE limit; found by luigi_345 on IRC

    - Fix link to Debian .mkshrc

    - Cease exporting $RANDOM (Debian #760857)

    - Fix C99 compatibility

    - Work around klibc bug causing a coredump (Debian
      #763842)

    - Use issetugid(2) as additional check if we are
      FPRIVILEGED

    - SECURITY: do not permit += from environment

    - Fix more field splitting bugs reported by Stephane
      Chazelas and mikeserv; document current status wrt.
      ambiguous ones as testcases too

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1149626"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-October/140364.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb321339"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mksh package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mksh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^20([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 20.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC20", reference:"mksh-50c-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mksh");
}
