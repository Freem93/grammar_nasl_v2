#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-10640.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47612);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/11 13:16:08 $");

  script_cve_id("CVE-2010-0831", "CVE-2010-2322");
  script_bugtraq_id(37128, 41006, 41009);
  script_xref(name:"FEDORA", value:"2010-10640");

  script_name(english:"Fedora 12 : gcc-4.4.4-10.fc12 / libtool-2.2.6-18.fc12.1 (2010-10640)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Fedora host is missing one or more security updates :

gcc-4.4.4-10.fc12 :

  - Wed Jun 30 2010 Jakub Jelinek <jakub at redhat.com>
    4.4.4-10

    - update from gcc-4_4-branch

    - PRs fortran/43841, fortran/43843,
      tree-optimization/44683

    - fix qualified-id as template argument handling
      (#605761, PR c++/44587)

    - -Wunused-but-set-* static_cast fix (PR c++/44682)

    - VTA backports

    - PRs debug/44610, debug/44668, debug/44694

    - unswitching fixes (PR middle-end/43866)

    - Thu Jun 24 2010 Jakub Jelinek <jakub at redhat.com>
      4.4.4-9

    - update from gcc-4_4-branch

    - PRs bootstrap/44426, bootstrap/44544, c++/44627,
      fortran/44536, libgcj/44216, target/39690,
      target/43740, target/44261, target/44481,
      target/44534, target/44615, testsuite/32843,
      testsuite/43739, tree-optimization/44508

  - VTA backports

    - PRs debug/43650, debug/44181, debug/44247

    - -Wunused-but-set-* ->*/.* fix (PR c++/44619)

    - undeprecate #ident and #sccs (#606069)

    - fixup dates in generated man pages even for fastjar
      and gcc/ man pages

    - don't realign stack on x86/x86-64 just because a
      DECL_ALIGN was set too high by expansion code
      (#603924, PR target/44542)

  - don't allow side-effects in inline-asm memory operands
    unless < or > is present in operand's constraint
    (#602359, PR middle-end/44492)

  - Fri Jun 11 2010 Jakub Jelinek <jakub at redhat.com>
    4.4.4-8

    - update from gcc-4_4-branch

    - fix demangler (PR other/43838)

    - VTA backports

    - further var-tracking speedup (#598310, PR debug/41371)

    - for typedefs in non-template classes adjust underlying
      type to emit proper debug info (#601893)

  - fix up fastjar directory traversal bugs (CVE-2010-0831)

    - Tue Jun 8 2010 Jakub Jelinek <jakub at redhat.com>
      4.4.4-7

    - update from gcc-4_4-branch

    - PRs c++/43555, fortran/42900, fortran/44360,
      libfortran/41169, libgcj/38251, libobjc/36610,
      libstdc++/32499, pch/14940, rtl-optimization/39580,
      target/44075, target/44169, target/44199

  - VTA backports

    - PRs debug/44367, debug/44375, rtl-optimization/44013,
      tree-optimization/44182

  - speed up var-tracking (#598310, PR debug/41371)

    - -Wunused-but-set-* bugfixes

    - PRs c++/44361, c++/44362, c++/44412, c++/44443,
      c++/44444

    - fix -mno-fused-madd -mfma4 on i?86/x86_64 (PR
      target/44338)

    - use GCJ_PROPERTIES=jdt.compiler.useSingleThread=true
      when building classes with ecj1 (#524155)

  - Tue May 25 2010 Jakub Jelinek <jakub at redhat.com>
    4.4.4-5

    - update from gcc-4_4-branch

    - PRs bootstrap/43870, debug/44205, target/43733,
      target/44074, target/44202, target/44245,
      tree-optimization/43845

  - fix cv-qual issue with function types (#593750, PR
    c++/44193)

[plus 297 lines in the Changelog]

libtool-2.2.6-18.fc12.1 :

  - Wed Jun 30 2010 Jakub Jelinek <jakub at redhat.com>
    2.2.6-18.fc12.1

    - rebuilt for gcc 4.4.4

    - Thu Jan 21 2010 Jakub Jelinek <jakub at redhat.com>
      2.2.6-18

    - rebuilt for gcc 4.4.3

    - Wed Dec 2 2009 Karsten Hopp <karsten at redhat.com>
      2.2.6-17

    - fix directory name used in libtool tarball

    - Wed Dec 2 2009 Karsten Hopp <karsten at redhat.com>
      2.2.6-16

    - update to 2.2.6b, fixes CVE-2009-3736: libltdl may
      load and execute code from a library in the current
      directory

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=594497"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/043780.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b27a553"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-July/043781.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8caae5a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gcc and / or libtool packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libtool");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/07");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"gcc-4.4.4-10.fc12")) flag++;
if (rpm_check(release:"FC12", reference:"libtool-2.2.6-18.fc12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc / libtool");
}
