#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1291-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(91159);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/02/27 15:13:34 $");

  script_cve_id("CVE-2015-7704", "CVE-2015-7705", "CVE-2015-7974", "CVE-2016-1547", "CVE-2016-1548", "CVE-2016-1549", "CVE-2016-1550", "CVE-2016-1551", "CVE-2016-2516", "CVE-2016-2517", "CVE-2016-2518", "CVE-2016-2519");
  script_osvdb_id(129309, 129310, 133387, 137711, 137712, 137713, 137714, 137731, 137732, 137733, 137734, 137735);

  script_name(english:"SUSE SLED12 / SLES12 Security Update : ntp (SUSE-SU-2016:1291-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ntp to 4.2.8p7 fixes the following issues :

  - CVE-2016-1547, bsc#977459: Validate crypto-NAKs, AKA:
    CRYPTO-NAK DoS.

  - CVE-2016-1548, bsc#977461: Interleave-pivot

  - CVE-2016-1549, bsc#977451: Sybil vulnerability:
    ephemeral association attack.

  - CVE-2016-1550, bsc#977464: Improve NTP security against
    buffer comparison timing attacks.

  - CVE-2016-1551, bsc#977450: Refclock impersonation
    vulnerability

  - CVE-2016-2516, bsc#977452: Duplicate IPs on unconfig
    directives will cause an assertion botch in ntpd.

  - CVE-2016-2517, bsc#977455: remote configuration
    trustedkey/ requestkey/controlkey values are not
    properly validated.

  - CVE-2016-2518, bsc#977457: Crafted addpeer with hmode >
    7 causes array wraparound with MATCH_ASSOC.

  - CVE-2016-2519, bsc#977458: ctl_getitem() return value
    not always checked.

  - This update also improves the fixes for: CVE-2015-7704,
    CVE-2015-7705, CVE-2015-7974

Bugs fixed :

  - Restrict the parser in the startup script to the first
    occurrance of 'keys' and 'controlkey' in ntp.conf
    (bsc#957226).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/957226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977457"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977459"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977461"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977464"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7704.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7974.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1548.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1549.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1550.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1551.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2516.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2518.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2519.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161291-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8baba8d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-764=1

SUSE Linux Enterprise Desktop 12-SP1 :

zypper in -t patch SUSE-SLE-DESKTOP-12-SP1-2016-764=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (os_ver == "SLES12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! ereg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"ntp-4.2.8p7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ntp-debuginfo-4.2.8p7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ntp-debugsource-4.2.8p7-11.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"ntp-doc-4.2.8p7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ntp-4.2.8p7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ntp-debuginfo-4.2.8p7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ntp-debugsource-4.2.8p7-11.1")) flag++;
if (rpm_check(release:"SLED12", sp:"1", cpu:"x86_64", reference:"ntp-doc-4.2.8p7-11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
