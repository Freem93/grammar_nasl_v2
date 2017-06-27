#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-5840.
#

include("compat.inc");

if (description)
{
  script_id(82887);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/10/19 23:14:51 $");

  script_xref(name:"FEDORA", value:"2015-5840");

  script_name(english:"Fedora 20 : perl-Module-Signature-0.78-1.fc20 / perl-Test-Signature-1.11-1.fc20 (2015-5840)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update addresses various security issues in perl-Module-Signature
as described below. The default behavior is also changed so as to
ignore any MANIFEST.SKIP files unless a 'skip' parameter is specified.
An updated version of perl-Test-Signature that accounts for the
changed default behavior is included in this update.

Security issues :

  - Module::Signature before version 0.75 could be tricked
    into interpreting the unsigned portion of a SIGNATURE
    file as the signed portion due to faulty parsing of the
    PGP signature boundaries.

  - When verifying the contents of a CPAN module,
    Module::Signature before version 0.75 ignored some files
    in the extracted tarball that were not listed in the
    signature file. This included some files in the t/
    directory that would execute automatically during 'make
    test'.

  - Module::Signature before version 0.75 used two argument
    open() calls to read the files when generating checksums
    from the signed manifest. This allowed embedding
    arbitrary shell commands into the SIGNATURE file that
    would execute during the signature verification process.

  - Module::Signature before version 0.75 has been loading
    several modules at runtime inside the extracted module
    directory. Modules like Text::Diff are not guaranteed to
    be available on all platforms and could be added to a
    malicious module so that they would load from the '.'
    path in @INC.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1209911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1209915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1209917"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1209918"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154822.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3efb4763"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-April/154823.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ce6e6aa"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected perl-Module-Signature and / or perl-Test-Signature
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Module-Signature");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Test-Signature");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:20");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");
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
if (rpm_check(release:"FC20", reference:"perl-Module-Signature-0.78-1.fc20")) flag++;
if (rpm_check(release:"FC20", reference:"perl-Test-Signature-1.11-1.fc20")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-Module-Signature / perl-Test-Signature");
}
