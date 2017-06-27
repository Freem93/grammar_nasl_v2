#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-17218.
#

include("compat.inc");

if (description)
{
  script_id(62846);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/09 15:27:58 $");

  script_cve_id("CVE-2012-4730", "CVE-2012-4732", "CVE-2012-4734", "CVE-2012-4884", "CVE-2012-6578", "CVE-2012-6579", "CVE-2012-6580", "CVE-2012-6581");
  script_bugtraq_id(56290);
  script_xref(name:"FEDORA", value:"2012-17218");

  script_name(english:"Fedora 16 : rt3-3.8.15-1.fc16 (2012-17218)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"----------------------------------------------------------------------
---------- ChangeLog :

  - Sun Oct 28 2012 Ralf Corsepius <corsepiu at
    fedoraproject.org> - 3.8.15-1

    - Upstream update (RH BZ 870407, CVE-2012-4730,
      CVE-2012-4732, CVE-2012-4734, CVE-2012-4735,
      CVE-2012-4884).

  - Sat Oct 6 2012 Ralf Corsepius <corsepiu at
    fedoraproject.org> - 3.8.14-1

    - Upstream update.

    - Sat Jun 2 2012 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.13-1

    - Upstream update.

    - Tue May 22 2012 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.12-1

    - Upstream update.

    - Address various CVEs (BZ 824082).

    - Thu Feb 2 2012 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.11-7

    - Fix shebangs.

    - Make testsuite files executable (enables rpm's perl
      module dep tracking).

    - Build *-tests, iff devel_mode was given.

    - Misc. specfile massaging.

    - Tue Jan 31 2012 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.11-6

    - Misc. specfile improvements.

    - Tue Jan 31 2012 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.11-5

    - Rewrite *-tests package (Don't use tests macros).

    - Mon Jan 30 2012 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.11-4

    - Rename rpmbuild option with_tests into with_runtests.

    - Add rt3-tests subpackage.

    - Add README.tests.

    - Remove removal of ${RT3_LIBDIR}/t (Fixed by upstream).

    - Rework R:/BR:.

    - Use %{__rm} instead of /bin/rm.

    - Misc minor spec file cleanup.

    - Wed Jan 18 2012 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.11-3

    - Fix typo in filter rules.

    - Add lexdir, manualdir, RT3_LEXDIR.

    - Mon Jan 16 2012 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.11-2

    - Remove redundant R: config(rt3), Remove P:
      config(rt3).

    - Rewrite filter rules.

    - Sun Jan 15 2012 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.11-1

    - Upstream update.

    - Tue Jan 10 2012 Ralf Corsepius <corsepiu at
      fedoraproject.org> - 3.8.10-5

    - Fix broken dependency filtering having been added in
      *-4.

    - Spec file cleanup.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=870406"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-November/091178.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32780728"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected rt3 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rt3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"rt3-3.8.15-1.fc16")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rt3");
}
