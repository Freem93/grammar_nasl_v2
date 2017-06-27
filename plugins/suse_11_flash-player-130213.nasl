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
  script_id(64636);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/25 23:41:53 $");

  script_cve_id("CVE-2013-0637", "CVE-2013-0638", "CVE-2013-0639", "CVE-2013-0642", "CVE-2013-0644", "CVE-2013-0645", "CVE-2013-0647", "CVE-2013-0649", "CVE-2013-1365", "CVE-2013-1366", "CVE-2013-1367", "CVE-2013-1368", "CVE-2013-1369", "CVE-2013-1370", "CVE-2013-1372", "CVE-2013-1373", "CVE-2013-1374");

  script_name(english:"SuSE 11.2 Security Update : flash-player (SAT Patch Number 7338)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for flash-player to version 11.2.202.270, tracked as
ABSP13-05
<ttp://www.adobe.com/support/security/bulletins/apsb13-05.html> ,
contains fixes for the following security issues :

  - Several buffer overflow vulnerabilities that could lead
    to code execution. (CVE-2013-0642 / CVE-2013-0645 /
    CVE-2013-1365 / CVE-2013-1366 / CVE-2013-1367 /
    CVE-2013-1368 / CVE-2013-1369 / CVE-2013-1370 /
    CVE-2013-1372 / CVE-2013-1373)

  - Use-after-free vulnerabilities that could lead to code
    execution. ( CVE-2013-0644 / CVE-2013-0649 /
    CVE-2013-1374)

  - An integer overflow vulnerability that could lead to
    code execution. (CVE-2013-0639)

  - Two memory corruption vulnerabilities that could lead to
    code execution. (CVE-2013-0638 / CVE-2013-0647)

  - An information disclosure vulnerability. (CVE-2013-0637)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=803485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0637.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0638.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0639.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0642.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0644.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0645.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0647.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-0649.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1365.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1366.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1367.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1368.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1369.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1370.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1372.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1373.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1374.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7338.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"flash-player-11.2.202.270-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"flash-player-gnome-11.2.202.270-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"flash-player-kde4-11.2.202.270-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"flash-player-11.2.202.270-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"flash-player-gnome-11.2.202.270-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"flash-player-kde4-11.2.202.270-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
