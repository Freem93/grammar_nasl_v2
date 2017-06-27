#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:3046-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(95625);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2016/12/27 20:33:26 $");

  script_cve_id("CVE-2010-2074", "CVE-2016-9422", "CVE-2016-9423", "CVE-2016-9424", "CVE-2016-9425", "CVE-2016-9434", "CVE-2016-9435", "CVE-2016-9436", "CVE-2016-9437", "CVE-2016-9438", "CVE-2016-9439", "CVE-2016-9440", "CVE-2016-9441", "CVE-2016-9442", "CVE-2016-9443", "CVE-2016-9621", "CVE-2016-9622", "CVE-2016-9623", "CVE-2016-9624", "CVE-2016-9625", "CVE-2016-9626", "CVE-2016-9627", "CVE-2016-9628", "CVE-2016-9629", "CVE-2016-9630", "CVE-2016-9631", "CVE-2016-9632", "CVE-2016-9633");
  script_bugtraq_id(40837);
  script_osvdb_id(65538, 147564, 147565, 147567, 147577, 147578, 147579, 147580, 147581, 147582, 147583, 147584, 147587, 147589, 147591, 147592, 147782, 147783, 147784, 147785);

  script_name(english:"SUSE SLES11 Security Update : w3m (SUSE-SU-2016:3046-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for w3m fixes the following issues :

  - update to debian git version (bsc#1011293) addressed
    security issues: CVE-2016-9621: w3m:
    global-buffer-overflow write (bsc#1012020)
    CVE-2016-9622: w3m: null deref (bsc#1012021)
    CVE-2016-9623: w3m: null deref (bsc#1012022)
    CVE-2016-9624: w3m: near-null deref (bsc#1012023)
    CVE-2016-9625: w3m: stack overflow (bsc#1012024)
    CVE-2016-9626: w3m: stack overflow (bsc#1012025)
    CVE-2016-9627: w3m: heap overflow read + deref
    (bsc#1012026) CVE-2016-9628: w3m: null deref
    (bsc#1012027) CVE-2016-9629: w3m: null deref
    (bsc#1012028) CVE-2016-9630: w3m: global-buffer-overflow
    read (bsc#1012029) CVE-2016-9631: w3m: null deref
    (bsc#1012030) CVE-2016-9632: w3m: global-buffer-overflow
    read (bsc#1012031) CVE-2016-9633: w3m: OOM (bsc#1012032)
    CVE-2016-9434: w3m: null deref (bsc#1011283)
    CVE-2016-9435: w3m: use uninit value (bsc#1011284)
    CVE-2016-9436: w3m: use uninit value (bsc#1011285)
    CVE-2016-9437: w3m: write to rodata (bsc#1011286)
    CVE-2016-9438: w3m: null deref (bsc#1011287)
    CVE-2016-9439: w3m: stack overflow (bsc#1011288)
    CVE-2016-9440: w3m: near-null deref (bsc#1011289)
    CVE-2016-9441: w3m: near-null deref (bsc#1011290)
    CVE-2016-9442: w3m: potential heap buffer corruption
    (bsc#1011291) CVE-2016-9443: w3m: null deref
    (bsc#1011292)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011269"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011272"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011285"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011286"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1011293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012028"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012029"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012030"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/1012032"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2010-2074.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9422.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9423.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9424.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9425.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9434.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9435.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9436.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9437.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9438.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9440.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9441.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9442.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9443.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9621.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9622.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9623.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9624.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9625.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9626.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9627.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9628.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9629.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9630.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9631.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9632.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-9633.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20163046-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7fc713e7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-w3m-12875=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-w3m-12875=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:w3m");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/08");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"w3m-0.5.3.git20161120-4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "w3m");
}
