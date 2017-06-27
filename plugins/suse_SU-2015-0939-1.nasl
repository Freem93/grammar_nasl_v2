#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0939-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83855);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2015-0255");
  script_bugtraq_id(72578);
  script_osvdb_id(118221);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : tigervnc, fltk (SUSE-SU-2015:0939-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"tigervnc and fltk were updated to fix security issues and non-security
bugs.

This security issue was fixed :

  - CVE-2015-0255: Information leak in the XkbSetGeometry
    request of X servers (bnc#915810).

These non-security issues were fixed :

  - vncviewer-tigervnc does not display mouse cursor shape
    changes (bnc#908738).

  - vnc module for Xorg fails to load on startup, module
    mismatch (bnc#911577).

  - An Xvnc session may become unusable when user logs out
    (bnc#920969)

fltk was updated to fix one non-security issue :

  - vncviewer-tigervnc does not display mouse cursor shape
    changes (bnc#908738).

Additionally tigervnc was updated to 1.4.1, the contained X server was
updated to to 1.15.2.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/908738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/911577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/915810"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/920969"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0255.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150939-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2459e9b7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12 :

zypper in -t patch SUSE-SLE-SDK-12-2015-210=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-210=1

SUSE Linux Enterprise Desktop 12 :

zypper in -t patch SUSE-SLE-DESKTOP-12-2015-210=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:fltk-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfltk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfltk1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tigervnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tigervnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tigervnc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xorg-x11-Xvnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/27");
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
if (rpm_check(release:"SLES12", sp:"0", reference:"fltk-debugsource-1.3.2-10.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfltk1-1.3.2-10.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libfltk1-debuginfo-1.3.2-10.2")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"tigervnc-1.4.1-32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"tigervnc-debuginfo-1.4.1-32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"tigervnc-debugsource-1.4.1-32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"xorg-x11-Xvnc-1.4.1-32.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"xorg-x11-Xvnc-debuginfo-1.4.1-32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"fltk-debugsource-1.3.2-10.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libfltk1-1.3.2-10.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"libfltk1-debuginfo-1.3.2-10.2")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"tigervnc-1.4.1-32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"tigervnc-debuginfo-1.4.1-32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"tigervnc-debugsource-1.4.1-32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xorg-x11-Xvnc-1.4.1-32.1")) flag++;
if (rpm_check(release:"SLED12", sp:"0", cpu:"x86_64", reference:"xorg-x11-Xvnc-debuginfo-1.4.1-32.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tigervnc / fltk");
}
