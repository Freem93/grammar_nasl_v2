#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79760);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/06 16:28:19 $");

  script_cve_id("CVE-2013-6497", "CVE-2014-9050");

  script_name(english:"SuSE 11.3 Security Update : clamav (SAT Patch Number 10016)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"clamav was updated to version 0.98.5 to fix three security issues and
several non-security issues.

These security issues have been fixed :

  - Crash when scanning maliciously crafted yoda's crypter
    files. (CVE-2013-6497)

  - Heap-based buffer overflow when scanning crypted PE
    files. (CVE-2014-9050)

  - Crash when using 'clamscan -a'. These non-security
    issues have been fixed :

  - Support for the XDP file format and extracting,
    decoding, and scanning PDF files within XDP files.

  - Addition of shared library support for LLVM versions 3.1
    - 3.5 for the purpose of just-in-time(JIT) compilation
    of ClamAV bytecode signatures.

  - Enhancements to the clambc command line utility to
    assist ClamAV bytecode signature authors by providing
    introspection into compiled bytecode programs.

  - Resolution of many of the warning messages from ClamAV
    compilation.

  - Improved detection of malicious PE files.

  - ClamAV 0.98.5 now works with OpenSSL in FIPS compliant
    mode. (bnc#904207)

  - Fix server socket setup code in clamd. (bnc#903489)

  - Change updateclamconf to prefer the state of the old
    config file even for commented-out options. (bnc#903719)

  - Fix infinite loop in clamdscan when clamd is not
    running.

  - Fix buffer underruns when handling multi-part MIME email
    attachments.

  - Fix configuration of OpenSSL on various platforms.

  - Fix linking issues with libclamunrar."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=903489"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=903719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=904207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=906077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=906770"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-6497.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-9050.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:clamav");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"clamav-0.98.5-0.5.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"clamav-0.98.5-0.5.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"clamav-0.98.5-0.5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
