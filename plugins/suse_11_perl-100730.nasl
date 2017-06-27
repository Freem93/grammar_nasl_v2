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
  script_id(50956);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_cve_id("CVE-2010-1168", "CVE-2010-1447");

  script_name(english:"SuSE 11 / 11.1 Security Update : Perl (SAT Patch Numbers 2833 / 2834)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"perl Safe.pm module was affected by two problems where attackers could
break out of such a safed execution (CVE-2010-1447 / CVE-2010-1168).
This update fixes this problem.

It also fixes the following bugs :

  - fix tell cornercase [bnc#596167]

  - fix regex memory leak [bnc#557636]

  - also run h2ph on /usr/include/linux [bnc#603840]

  - backport h2ph include fix from 5.12.0 [bnc#601242]

  - fix segfault when using regexpes in threaded apps
    [bnc#588338]

  - backport upstream fixes for POSIX module to avoid
    clashes with Fcntl [bnc#446098], [bnc#515948]

  - backport upstream fix for ISA assertion failure
    [bnc#528423]

  - move unicode files from perl-doc to perl, otherwise some
    perl modules will not work"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=446098"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=515948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=528423"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=557636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=588338"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=596167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=601242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=603840"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605918"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605928"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1168.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1447.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 2833 / 2834 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:perl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:perl-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"perl-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"perl-base-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"perl-doc-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"perl-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"perl-32bit-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"perl-base-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"perl-doc-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"perl-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"perl-base-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"perl-doc-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"perl-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"perl-32bit-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"perl-base-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"perl-doc-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"perl-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"perl-base-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"perl-doc-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"perl-32bit-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"perl-32bit-5.10.0-64.44.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"perl-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"perl-base-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"perl-doc-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"perl-32bit-5.10.0-64.48.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"perl-32bit-5.10.0-64.48.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
