#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1528-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(91655);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/04/18 13:37:18 $");

  script_cve_id("CVE-2015-8325", "CVE-2016-1908", "CVE-2016-3115");
  script_osvdb_id(132941, 135714, 137226);

  script_name(english:"SUSE SLES11 Security Update : openssh (SUSE-SU-2016:1528-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"openssh was updated to fix three security issues.

These security issues were fixed :

  - CVE-2016-3115: Multiple CRLF injection vulnerabilities
    in session.c in sshd in OpenSSH allowed remote
    authenticated users to bypass intended shell-command
    restrictions via crafted X11 forwarding data, related to
    the (1) do_authenticated1 and (2) session_x11_req
    functions (bsc#970632).

  - CVE-2016-1908: Possible fallback from untrusted to
    trusted X11 forwarding (bsc#962313).

  - CVE-2015-8325: Ignore PAM environment vars when
    UseLogin=yes (bsc#975865).

These non-security issues were fixed :

  - Correctly parse GSSAPI KEX algorithms (bsc#961368)

  - More verbose FIPS mode/CC related documentation in
    README.FIPS (bsc#965576, bsc#960414)

  - Fix PRNG re-seeding (bsc#960414, bsc#729190)

  - Disable DH parameters under 2048 bits by default and
    allow lowering the limit back to the RFC 4419 specified
    minimum through an option (bsc#932483, bsc#948902)

  - Allow empty Match blocks (bsc#961494)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/729190"
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
    value:"https://bugzilla.suse.com/960414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/961494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/962313"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/965576"
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
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161528-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c300fb7d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4 :

zypper in -t patch slessp4-openssh-12603=1

SUSE Linux Enterprise Debuginfo 11-SP4 :

zypper in -t patch dbgsp4-openssh-12603=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openssh-helpers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/17");
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
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"openssh-6.6p1-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"openssh-askpass-gnome-6.6p1-21.3")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"openssh-fips-6.6p1-21.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"openssh-helpers-6.6p1-21.1")) flag++;


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
