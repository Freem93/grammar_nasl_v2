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
  script_id(57139);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2010-4818", "CVE-2010-4819");

  script_name(english:"SuSE 11.1 Security Update : Xorg (SAT Patch Number 5294)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for xorg-x11-server and xorg-x11-libs brings improved
compatibility fixes and enhancements for X.org. The main feature is
support for Multi monitor configurations with independent heads, which
used to be supported with SUSE Linux Enterprise 10 (VGA Arbitration
Support).

During update to Service Pack 1, the support for AppGroup Extension
was removed from the X11 Server. This update fixes this regression and
adds back the support. (bnc#709943)

Additionally this update fixes bugs in the AppGroup Extensions, which
resulted in Xserver crashes. (bnc#716355)

It also fixes an issue with changing the mouse mode to absolute.
(bnc#704467)

It also fixes an issue with button release on non-core pointing
devices. (bnc#698281)

In addition to that, multiple missing or incorrect bounds checking
flaws were fixed in in GLX (CVE-2010-4818) and in the X Render
Extension (CVE-2010-4819) were fixed, which could be used to crash the
X server.

A regression in handling TWM was fixed as well. (bnc#709987)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=648287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=648290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=698281"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704467"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=709943"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=709987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=714677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=716355"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4818.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-4819.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5294.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpciaccess0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpciaccess0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpciaccess0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-libs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libpciaccess0-7.4_0.11.0-0.4.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"libpciaccess0-devel-7.4_0.11.0-0.4.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xorg-x11-Xvnc-7.4-27.40.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xorg-x11-devel-7.4-8.26.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xorg-x11-libs-7.4-8.26.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xorg-x11-server-7.4-27.40.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xorg-x11-server-extra-7.4-27.40.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libpciaccess0-7.4_0.11.0-0.4.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libpciaccess0-32bit-7.4_0.11.0-0.4.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"libpciaccess0-devel-7.4_0.11.0-0.4.6.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-Xvnc-7.4-27.40.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-devel-7.4-8.26.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-libs-7.4-8.26.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-libs-32bit-7.4-8.26.32.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-server-7.4-27.40.50.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-server-extra-7.4-27.40.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"libpciaccess0-7.4_0.11.0-0.4.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"xorg-x11-Xvnc-7.4-27.40.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"xorg-x11-libs-7.4-8.26.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"xorg-x11-server-7.4-27.40.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"xorg-x11-server-extra-7.4-27.40.50.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"libpciaccess0-32bit-7.4_0.11.0-0.4.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"xorg-x11-libs-32bit-7.4-8.26.32.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"libpciaccess0-32bit-7.4_0.11.0-0.4.6.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"x86_64", reference:"xorg-x11-libs-32bit-7.4-8.26.32.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
