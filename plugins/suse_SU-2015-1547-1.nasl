#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:1547-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(85929);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/27 20:14:33 $");

  script_cve_id("CVE-2015-4000", "CVE-2015-5352", "CVE-2015-5600", "CVE-2015-6563", "CVE-2015-6564");
  script_bugtraq_id(74733, 75525);
  script_osvdb_id(122331, 124008, 124938, 126030, 126033);

  script_name(english:"SUSE SLES11 Security Update : openssh (SUSE-SU-2015:1547-1) (Logjam)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"openssh was updated to fix several security issues and bugs.

These security issues were fixed :

  - CVE-2015-5352: The x11_open_helper function in
    channels.c in ssh in OpenSSH when ForwardX11Trusted mode
    is not used, lacked a check of the refusal deadline for
    X connections, which made it easier for remote attackers
    to bypass intended access restrictions via a connection
    outside of the permitted time window (bsc#936695).

  - CVE-2015-5600: The kbdint_next_device function in
    auth2-chall.c in sshd in OpenSSH did not properly
    restrict the processing of keyboard-interactive devices
    within a single connection, which made it easier for
    remote attackers to conduct brute-force attacks or cause
    a denial of service (CPU consumption) via a long and
    duplicative list in the ssh -oKbdInteractiveDevices
    option, as demonstrated by a modified client that
    provides a different password for each pam element on
    this list (bsc#938746).

  - CVE-2015-4000: Removed and disabled weak DH groups to
    address LOGJAM (bsc#932483).

  - Hardening patch to fix sftp RCE (bsc#903649).

  - CVE-2015-6563: The monitor component in sshd in OpenSSH
    accepted extraneous username data in
    MONITOR_REQ_PAM_INIT_CTX requests, which allowed local
    users to conduct impersonation attacks by leveraging any
    SSH login access in conjunction with control of the sshd
    uid to send a crafted MONITOR_REQ_PWNAM request, related
    to monitor.c and monitor_wrap.c.

  - CVE-2015-6564: Use-after-free vulnerability in the
    mm_answer_pam_free_ctx function in monitor.c in sshd in
    OpenSSH might have allowed local users to gain
    privileges by leveraging control of the sshd uid to send
    an unexpectedly early MONITOR_REQ_PAM_FREE_CTX request.

These non-security issues were fixed :

  - bsc#914309: sshd inherits oom_adj -17 on SIGHUP causing
    DoS potential for oom_killer.

  - bsc#673532: limits.conf fsize change in SLES10SP3
    causing problems to WebSphere mqm user.

  - bsc#916549: Fixed support for aesXXX-gcm@openssh.com.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/673532"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/903649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/905118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/916549"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/936695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/943010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5600.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6563.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6564.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20151547-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?188f3ab8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for VMWare 11-SP3 :

zypper in -t patch slessp3-openssh-12087=1

SUSE Linux Enterprise Server 11-SP3 :

zypper in -t patch slessp3-openssh-12087=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/09");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/14");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssh-6.2p2-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssh-askpass-6.2p2-0.17.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssh-askpass-gnome-6.2p2-0.17.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh");
}
