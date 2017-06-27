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
  script_id(74088);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/11/20 12:01:11 $");

  script_cve_id("CVE-2014-0510", "CVE-2014-0516", "CVE-2014-0517", "CVE-2014-0518", "CVE-2014-0519", "CVE-2014-0520");

  script_name(english:"SuSE 11.3 Security Update : flash-player (SAT Patch Number 9259)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adobe flash-player was updated to version 11.2.202.359 to resolve
several security issues :

  - Remote attackers could execute arbitrary code and bypass
    a sandbox protection mechanism via unspecified vectors.
    (CVE-2014-0510)

  - Remote attackers could bypass the Same Origin Policy via
    unspecified vectors. (CVE-2014-0516)

  - Bypass intended access restrictions via unspecified
    vectors. (CVE-2014-0517 / CVE-2014-0518 / CVE-2014-0519
    / CVE-2014-0520) More information can be found at
    http://helpx.adobe.com/security/products/flash-player/ap
    sb14-14.html ."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=877649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0510.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0516.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0519.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0520.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 9259.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"flash-player-11.2.202.359-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"flash-player-gnome-11.2.202.359-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"flash-player-kde4-11.2.202.359-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"flash-player-11.2.202.359-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"flash-player-gnome-11.2.202.359-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"flash-player-kde4-11.2.202.359-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
