#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1833-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(86648);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/04/05 21:32:29 $");

  script_cve_id("CVE-2015-5276");
  script_osvdb_id(127770);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : gcc48 (SUSE-SU-2015:1833-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for GCC 4.8 provides the following fixes :

  - Fix C++11 std::random_device short read issue that could
    lead to predictable randomness. (CVE-2015-5276,
    bsc#945842)

  - Fix linker segmentation fault when building SLOF on
    ppc64le. (bsc#949000)

  - Fix no_instrument_function attribute handling on PPC64
    with

    -mprofile-kernel. (bsc#947791)

  - Fix internal compiler error with aarch64 target using
    PCH and builtin functions. (bsc#947772)

  - Fix libffi issues on aarch64. (bsc#948168)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/947791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5276.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151833-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d44ba09"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-756=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-756=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-756=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-756=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cpp48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-c++-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-gij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-gij-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gcc48-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libasan0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libffi48-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcj48");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcj48-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcj48-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcj48-jar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgcj_bc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libstdc++48-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan0-32bit-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan0-32bit-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan0-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"x86_64", reference:"libasan0-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"libffi48-debugsource-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cpp48-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cpp48-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-c++-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-c++-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-debugsource-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-locale-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libstdc++48-devel-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"gcc48-32bit-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libstdc++48-devel-32bit-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cpp48-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"cpp48-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc48-32bit-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc48-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc48-c++-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc48-c++-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc48-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc48-debugsource-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc48-gij-32bit-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc48-gij-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc48-gij-debuginfo-32bit-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"gcc48-gij-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libasan0-32bit-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libasan0-32bit-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libasan0-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libasan0-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcj48-32bit-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcj48-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcj48-debuginfo-32bit-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcj48-debuginfo-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcj48-debugsource-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcj48-jar-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libgcj_bc1-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libstdc++48-devel-32bit-4.8.5-24.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libstdc++48-devel-4.8.5-24.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gcc48");
}
