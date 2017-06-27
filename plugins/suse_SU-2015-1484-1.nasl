#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1484-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85796);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2009-1364", "CVE-2015-0848", "CVE-2015-4588", "CVE-2015-4695", "CVE-2015-4696");
  script_bugtraq_id(34792, 74923, 75230, 75329, 75331);
  script_osvdb_id(122812, 123385, 123541, 123542);

  script_name(english:"SUSE SLED12 Security Update : libwmf (SUSE-SU-2015:1484-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"libwmf was updated to fix five security issues.

These security issues were fixed :

  - CVE-2009-1364: Fixed realloc return value usage
    (bsc#495842, bnc#831299)

  - CVE-2015-0848: Heap overflow on libwmf0.2-7 (bsc#933109)

  - CVE-2015-4588: DecodeImage() did not check that the
    run-length 'count' fits into the total size of the
    image, which could lead to a heap-based buffer overflow
    (bsc#933109)

  - CVE-2015-4695: meta_pen_create heap buffer over read
    (bsc#936058)

  - CVE-2015-4696: Use after free (bsc#936062)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/495842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/831299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936058"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936062"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2009-1364.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0848.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4588.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4695.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4696.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151484-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91f4dfcc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Workstation Extension 12 :

zypper in -t patch SUSE-SLE-WE-12-2015-481=1

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-481=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-481=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwmf-0_2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwmf-0_2-7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwmf-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/04");
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
if (! ereg(pattern:"^(SLED12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "x86_64") audit(AUDIT_ARCH_NOT, "x86_64", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLED12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwmf-0_2-7-0.2.8.4-242.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwmf-0_2-7-debuginfo-0.2.8.4-242.3")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libwmf-debugsource-0.2.8.4-242.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwmf");
}
