#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0117.
#

include("compat.inc");

if (description)
{
  script_id(85529);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-3238");
  script_bugtraq_id(75428);
  script_osvdb_id(123767);

  script_name(english:"OracleVM 3.3 : pam (OVMSA-2015-0117)");
  script_summary(english:"Checks the RPM output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - fix CVE-2015-3238 - DoS due to blocking pipe with very
    long password

  - make pam_pwhistory and pam_unix tolerant of opasswd file
    corruption

  - pam_userdb: allow any crypt hash algorithm to be used
    (#1119289)

  - pam_cracklib: improve documentation (#889233)

  - unbreak authentication if ld.so.preload is not empty

  - correct off by one error in account expiration
    calculation (#947011)

  - pam_console_apply: do not print error if console.perms.d
    is empty

  - properly handle all cases where crypt might return NULL
    (#1026203)

  - pam_limits: clarify documentation of maxsyslogins limit
    (#1028490)

  - pam_access: call DNS resolution only when necessary and
    cache results (#1029817)

  - pam_limits: nofile applies to file descriptors not files
    (#1040664)

  - pam_limits: check whether the utmp login entry is valid
    (#1054936)

  - correct URLs in spec file (#1071770)

  - pam_userdb: correct the example in man page (#1078779)

  - pam_selinux: canonicalize username for getseuser
    (#1083981)

  - pam_access: fix netgroup matching and @user@@netgroup
    parsing (#740233)

  - pam_tty_audit: allow for runtime backwards compatibility
    with old kernels

  - add option to pam_tty_audit to disable auditing of
    password input"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2015-August/000365.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5790b061"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pam package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:pam");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"pam-1.1.1-20.el6_7.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pam");
}
