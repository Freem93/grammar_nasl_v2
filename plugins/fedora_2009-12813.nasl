#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-12813.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43612);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/10/21 22:41:45 $");

  script_cve_id("CVE-2009-3736");
  script_bugtraq_id(37128);
  script_xref(name:"FEDORA", value:"2009-12813");

  script_name(english:"Fedora 12 : gcc-4.4.2-20.fc12 (2009-12813)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Dec 22 2009 Jakub Jelinek <jakub at redhat.com>
    4.4.2-20

    - fix MEM_SIZE of reload created stack slots (#548825,
      PR rtl-optimization/42429)

  - fix addition of one character long filenames in fastjar
    (#549493)

    - Thu Dec 17 2009 Jakub Jelinek <jakub at redhat.com>
      4.4.2-18

    - update from gcc-4_4-branch

    - PRs c++/42387

    - another C++ virtual dtors fix (PR c++/42386)

    - VTA mode and COND_EXEC fixes (PR debug/41679)

    - fix ICE in chrec_convert_1 (#547775)

    - fix debuginfo for optimized out TLS vars

    - use DW_AT_location with DW_OP_addr + DW_OP_stack_value
      instead of DW_AT_const_value with address in it, use
      DW_OP_addr + DW_OP_stack_value instead of
      DW_OP_implicit_value with address (#546017)

  - Mon Dec 14 2009 Jakub Jelinek <jakub at redhat.com>
    4.4.2-17

    - propagate TREE_NOTHROW/TREE_READONLY/DECL_PURE_P from
      ipa-pure-const and EH opt to all same body aliases
      (#547286)

  - don't emit DWARF location list entries with no location
    or DW_AT_location with empty blocks (PR debug/41473)

  - fix up AMD LWP support

    - don't crash when mangling C++ decls inside of
      middle-end generated functions (PR c++/41183)

  - Fri Dec 11 2009 Jakub Jelinek <jakub at redhat.com>
    4.4.2-16

    - update from gcc-4_4-branch

    - PRs c++/27425, c++/34274, c++/42301, fortran/42268,
      java/41991, libstdc++/42273, rtl-optimization/41574,
      target/41196, target/41939 target/42263

  - Wed Dec 9 2009 Jakub Jelinek <jakub at redhat.com>
    4.4.2-15

    - VTA backports

    - PRs debug/42166, debug/42234, debug/42244, debug/42299

    - fix handling of C++ COMDAT virtual destructors

    - some x86/x86_64 FMA4, XOP, ABM and LWP fixes

    - fix a decltype handling bug in templates (PR
      c++/42277)

    - Fri Dec 4 2009 Jakub Jelinek <jakub at redhat.com>
      4.4.2-14

    - update from gcc-4_4-branch

    - PRs libstdc++/42261, middle-end/42049

    - backport C++0x ICE fix from trunk (PR c++/42266)

    - fortran !$omp workshare improvements (PR
      fortran/35423)

    - FMA4 and XOP fixes

    - Wed Dec 2 2009 Jakub Jelinek <jakub at redhat.com>
      4.4.2-13

    - fix security issues in libltdl bundled within libgcj
      (CVE-2009-3736)

    - Wed Dec 2 2009 Jakub Jelinek <jakub at redhat.com>
      4.4.2-12

    - update from gcc-4_4-branch

    - PRs c++/42234, fortran/41278, fortran/41807,
      fortran/42162, target/42113, target/42165

  - don't ICE on -O256 (#539923)

    - fix -mregnames on ppc/ppc64

    - optimize even COMDAT constructors and destructors
      without virtual bases (PR c++/3187)

  - Mon Nov 23 2009 Jakub Jelinek <jakub at redhat.com>
    4.4.2-11

[plus 32 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=537941"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/033321.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?aa4ac9dc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gcc package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gcc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC12", reference:"gcc-4.4.2-20.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc");
}
