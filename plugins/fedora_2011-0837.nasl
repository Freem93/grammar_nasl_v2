#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-0837.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(52004);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/16 13:53:25 $");

  script_cve_id("CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-4253", "CVE-2010-4643");
  script_bugtraq_id(46031);
  script_osvdb_id(70711, 70712, 70713, 70714, 70715, 70716, 70717, 70718);
  script_xref(name:"FEDORA", value:"2011-0837");

  script_name(english:"Fedora 13 : openoffice.org-3.2.0-12.35.fc13 (2011-0837)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Jan 27 2011 Caolan McNamara <caolanm at redhat.com>-
    1:3.2.0-12.35

    - CVE-2010-3450 Extensions and filter package files

    - CVE-2010-3451 / CVE-2010-3452 RTF documents

    - CVE-2010-3453 / CVE-2010-3454 Word documents

    - CVE-2010-3689 LD_LIBRARY_PATH usage

    - CVE-2010-4253 PNG graphics

    - CVE-2010-4643 TGA graphics

    - Resolves: rhbz#648475 Crash in scanner dialog

    - Resolves: rhbz#657628 divide-by-zero

    - Resolves: rhbz#657718 Crash in SwObjectFormatterTxtFrm

    - Resolves: rhbz#660312 SDK setup script creates invalid
      variables (dtardon)

  - Resolves: rhbz#663780 extend neon mutex locking

    - Resoves: rhbz#577525 [abrt] crash in
      ImplRegionBase::~ImplRegionBase (dtardon)

  - Tue Oct 26 2010 Caolan McNamara <caolanm at redhat.com>
    - 1:3.2.0-12.34

    - Resolves: rhbz#636521 crash in undo in sc

    - Resolves: rhbz#641637 [abrt] [presentation-minimizer]
      crash in OptimizationStats::GetStatusValue (dtardon)

  - make LD_PRELOAD of libsalalloc_malloc.so work again
    (dtardon)

    - Resolves: rhbz#642996 [abrt]
      CffSubsetterContext::readDictOp (dtardon)

    - Fri Oct 15 2010 Caolan McNamara <caolanm at
      redhat.com> - 1:3.2.0-12.33

    - Resolves: rhbz#637838 Cropped pictures are displayed
      in entirety in handouts (dtardon)

  - Tue Oct 12 2010 Caolan McNamara <caolanm at redhat.com>
    - 1:3.2.0-12.32

    - Resolves: rhbz#568277 workaround to avoid the crash
      (dtardon)

    - Resolves: rhbz#631543 [abrt] crash on dereferencing
      dangling pointer passed down from SwCalc::Str2Double
      (dtardon)

  - Resolves: rhbz#631823 Line and Filling toolbar glitch on
    theme change (caolanm)

  - Resolves: rhbz#637738 threading problems with using
    libgcrypt via neon when libgcrypt which was initialized
    by cups to be non-thread safe (caolanm)

  - Resolves: rhbz#632326 [abrt] [docx] _Construct<long,
    long> crash (dtardon)

  - Fri Aug 13 2010 Caolan McNamara <caolanm at redhat.com>
    - 1:3.2.0-12.31

    - Resolves: rhbz#623800 gnome-shell/mutter focus
      problems

    - Thu Aug 12 2010 Caolan McNamara <caolanm at
      redhat.com> - 1:3.2.0-12.30

    - Resolves: rhbz#623609 CVE-2010-2935 CVE-2010-2936

    - Mon Aug 9 2010 Caolan McNamara <caolanm at redhat.com>
      - 1:3.2.0-12.29

    - Resolves: rhbz#601621 avoid using mmap for copying
      files

    - Sun Aug 8 2010 Caolan McNamara <caolanm at redhat.com>
      - 1:3.2.0-12.28

    - Resolves: rhbz#621248 32bit events in forms on 64bit

    - Resolves rhbz#618047 Brackets incorrectly render in
      presentations (dtardon)

  - Wed Aug 4 2010 Caolan McNamara <caolanm at redhat.com> -
    1:3.2.0-12.27

    - Resolves: rhbz#608114 cppu-lifecycle issues (caolanm)

    - Resolves: rhbz#566831 [abrt] crash in GetFrmSize
      (dtardon)

    - Resolves: rhbz#613278 [abrt] crash in SANE shutdown
      (caolanm)

    - Resolves: rhbz#620390 [abrt] crash in
      SfxViewFrame::GetFrame (dtardon)

    - Mon Jun 21 2010 Caolan McNamara <caolanm at
      redhat.com> - 1:3.2.0-12.26

[plus 34 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=602324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=640241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=640950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=640954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=641224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=641282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=658259"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=667588"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-February/054137.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc0856df"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:13");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC13", reference:"openoffice.org-3.2.0-12.35.fc13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org");
}
