#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1602-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93153);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2016-4953", "CVE-2016-4954", "CVE-2016-4955", "CVE-2016-4956", "CVE-2016-4957");
  script_osvdb_id(139280, 139281, 139282, 139283, 139284);

  script_name(english:"SUSE SLES11 Security Update : ntp (SUSE-SU-2016:1602-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ntp was updated to version 4.2.8p8 to fix five security issues.

These security issues were fixed :

  - CVE-2016-4953: Bad authentication demobilizes ephemeral
    associations (bsc#982065).

  - CVE-2016-4954: Processing spoofed server packets
    (bsc#982066).

  - CVE-2016-4955: Autokey association reset (bsc#982067).

  - CVE-2016-4956: Broadcast interleave (bsc#982068).

  - CVE-2016-4957: CRYPTO_NAK crash (bsc#982064).

These non-security issues were fixed :

  - Keep the parent process alive until the daemon has
    finished initialisation, to make sure that the PID file
    exists when the parent returns.

  - bsc#979302: Change the process name of the forking DNS
    worker process to avoid the impression that ntpd is
    started twice.

  - bsc#981422: Don't ignore SIGCHILD because it breaks
    wait().

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/979302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981422"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982064"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982066"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982068"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4953.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4954.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4955.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4956.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4957.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161602-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6e02639"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5 :

zypper in -t patch sleclo50sp3-ntp-12615=1

SUSE Manager Proxy 2.1 :

zypper in -t patch slemap21-ntp-12615=1

SUSE Manager 2.1 :

zypper in -t patch sleman21-ntp-12615=1

SUSE Linux Enterprise Server 11-SP3-LTSS :

zypper in -t patch slessp3-ntp-12615=1

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-ntp-12615=1

SUSE Linux Enterprise Debuginfo 11-SP3 :

zypper in -t patch dbgsp3-ntp-12615=1

SUSE Linux Enterprise Debuginfo 11-SP2 :

zypper in -t patch dbgsp2-ntp-12615=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(2|3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", reference:"ntp-4.2.8p8-47.3")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"ntp-doc-4.2.8p8-47.3")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"ntp-4.2.8p8-47.3")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"ntp-doc-4.2.8p8-47.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ntp");
}
