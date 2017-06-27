#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-6505.
#

include("compat.inc");

if (description)
{
  script_id(83201);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/10/19 23:14:52 $");

  script_xref(name:"FEDORA", value:"2015-6505");

  script_name(english:"Fedora 20 : mksh-50f-1.fc20 (2015-6505)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"R50f is a required security and bugfix release :

  - Add a patch marker for vendor patch versioning to mksh.1

    - SECURITY: make unset HISTFILE actually work

    - Document some more issues with the current history
      code

    - Remove some unused code

    - RCSID-only sync with OpenBSD, for bogus and irrelevant
      changes

    - Also disable field splitting for alias 'local= ypeset'

    - Fix read -n-1 to not be identical to read -N-1

    - Several fixes and improvements to lksh(1) and mksh(1)
      manpages

    - More code (int ' size_t), comment and testsuite fixes

    - Make dot.mkshrc more robust (LP#1441853)

    - Fix issues with IFS=' read, found by edualbus

    - Fix integer overflows related to file descriptor
      parsing, found by Pawel Wylecial (LP#1440685); reduce
      memory usage for I/O redirs

    - Document in the manpage how to set +-U according to
      the current locale settings via LANG/LC_* parameters
      (cf. Debian #782225)

    - Some code cleanup and restructuring

    - Handle number parsing and storing more carefully

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/156632.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4324e5e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mksh package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mksh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC20", reference:"mksh-50f-1.fc20")) flag++;


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
