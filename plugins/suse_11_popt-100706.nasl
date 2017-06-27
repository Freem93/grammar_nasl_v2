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
  script_id(50957);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_cve_id("CVE-2010-2059");

  script_name(english:"SuSE 11 / 11.1 Security Update : popt (SAT Patch Numbers 2647 / 2648)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a security problem where RPM misses to clear the
SUID/SGID bit of old files during package updates. (CVE-2010-2059)

Also the following bugs were fixed :

  - make 'rpmconfigcheck status' exit with 4 [bnc#592269]

  - do not use glibc for passwd/group lookups when --root is
    used [bnc#536256]

  - disable cpio md5 checking for repackaged rpms
    [bnc#572280]

  - Add rpm-4.4.2.3-no-order-rescan-limit.patch from
    upstream. (bnc#552622)

  - backport lazy statfs patch [fate#302038]

  - findksyms.diff: backport changes from Factory for
    fate#305945.

  - fix v4 rsa signature verification code [bnc#615409]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=536256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=552622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=572280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=592269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=610941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=615409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2059.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply SAT patch number 2647 / 2648 as appropriate."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:popt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:popt-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:rpm-32bit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/06");
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
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"popt-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"rpm-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"popt-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"popt-32bit-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"rpm-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"rpm-32bit-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"popt-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"rpm-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"popt-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"popt-32bit-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"rpm-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"rpm-32bit-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"popt-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"rpm-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"popt-32bit-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"rpm-32bit-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"popt-32bit-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"rpm-32bit-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"popt-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"rpm-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"popt-32bit-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"rpm-32bit-4.4.2.3-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"popt-32bit-1.7-37.18.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"rpm-32bit-4.4.2.3-37.18.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
