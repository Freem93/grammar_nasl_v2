#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:2388-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93735);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:10 $");

  script_cve_id("CVE-2015-8325", "CVE-2016-1908", "CVE-2016-3115", "CVE-2016-6210", "CVE-2016-6515");
  script_osvdb_id(132941, 135714, 137226, 141586, 142342);

  script_name(english:"SUSE SLES11 Security Update : openssh (SUSE-SU-2016:2388-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for OpenSSH fixes the following issues :

  - Prevent user enumeration through the timing of password
    processing. (bsc#989363, CVE-2016-6210)

  - Allow lowering the DH groups parameter limit in server
    as well as when GSSAPI key exchange is used.
    (bsc#948902)

  - Sanitize input for xauth(1). (bsc#970632, CVE-2016-3115)

  - Prevent X11 SECURITY circumvention when forwarding X11
    connections. (bsc#962313, CVE-2016-1908)

  - Disable DH parameters under 2048 bits by default and
    allow lowering the limit back to the RFC 4419 specified
    minimum through an option. (bsc#932483, bsc#948902)

  - Ignore PAM environment when using login. (bsc#975865,
    CVE-2015-8325)

  - Limit the accepted password length (prevents a possible
    denial of service). (bsc#992533, CVE-2016-6515)

  - Relax version requires for the openssh-askpass
    sub-package. (bsc#962794)

  - Avoid complaining about unset DISPLAY variable.
    (bsc#981654)

  - Initialize message id to prevent connection breakups in
    some cases. (bsc#959096)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/932483"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/948902"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/959096"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/970632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/975865"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/989363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/992533"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8325.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-1908.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3115.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6210.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-6515.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20162388-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f06ddb39"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 5:zypper in -t patch sleclo50sp3-openssh-12759=1

SUSE Manager Proxy 2.1:zypper in -t patch slemap21-openssh-12759=1

SUSE Manager 2.1:zypper in -t patch sleman21-openssh-12759=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-openssh-12759=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-openssh-12759=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-openssh-12759=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/27");
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
if (os_ver == "SLES11" && (! ereg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssh-6.2p2-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssh-askpass-6.2p2-0.33.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openssh-askpass-gnome-6.2p2-0.33.5")) flag++;


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
