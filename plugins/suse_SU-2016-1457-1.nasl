#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1457-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(91650);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:08 $");

  script_cve_id("CVE-2014-3566", "CVE-2015-8076", "CVE-2015-8077", "CVE-2015-8078");
  script_bugtraq_id(70574);
  script_osvdb_id(113251, 128212, 129883, 129884);

  script_name(english:"SUSE SLES12 Security Update : cyrus-imapd (SUSE-SU-2016:1457-1) (POODLE)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Previous versions of cyrus-imapd would not allow its
    users to disable old protocols like SSLv1 and SSLv2 that
    are unsafe due to various known attacks like BEAST and
    POODLE.
    https://bugzilla.cyrusimap.org/show_bug.cgi?id=3867
    remedies this issue by adding the configuration option
    'tls_versions' to the imapd.conf file. Note that users
    who upgrade existing installation of this package will
    *not* have their imapd.conf file overwritten, i.e. their
    IMAP server will continue to support SSLv1 and SSLv2
    like before. To disable support for those protocols,
    it's necessary to edit imapd.conf manually to state
    'tls_versions: tls1_0 tls1_1 tls1_2'. New installations,
    however, will have an imapd.conf file that contains
    these settings already, i.e. newly installed IMAP
    servers do *not* support SSLv1 and SSLv2 unless that
    support is explicitly enabled by the user. (bsc#901748)

  - An integer overflow vulnerability in cyrus-imapd's
    urlfetch range checking code was fixed. (CVE-2015-8076,
    CVE-2015-8077, CVE-2015-8078, bsc#981670, bsc#954200,
    bsc#954201)

  - Support for Elliptic Curve
    Diffie&Atilde;&cent;&Acirc;&#128;&Acirc;&#147;Hellman
    (ECDH) has been added to cyrus-imapd. (bsc#860611)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.cyrusimap.org/show_bug.cgi?id=3867"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/860611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/901748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/954201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3566.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8076.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8077.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8078.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161457-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c638d3d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12-SP1 :

zypper in -t patch SUSE-SLE-SERVER-12-SP1-2016-864=1

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2016-864=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-imapd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cyrus-imapd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-Cyrus-IMAP");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-Cyrus-IMAP-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-Cyrus-SIEVE-managesieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-Cyrus-SIEVE-managesieve-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0|1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"cyrus-imapd-debuginfo-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"cyrus-imapd-debugsource-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-Cyrus-IMAP-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-Cyrus-IMAP-debuginfo-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-Cyrus-SIEVE-managesieve-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"perl-Cyrus-SIEVE-managesieve-debuginfo-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cyrus-imapd-debuginfo-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"cyrus-imapd-debugsource-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-Cyrus-IMAP-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-Cyrus-IMAP-debuginfo-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-Cyrus-SIEVE-managesieve-2.3.18-37.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"perl-Cyrus-SIEVE-managesieve-debuginfo-2.3.18-37.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cyrus-imapd");
}
