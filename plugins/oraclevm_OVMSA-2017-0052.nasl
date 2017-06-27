#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0052.
#

include("compat.inc");

if (description)
{
  script_id(99079);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2017-2616");
  script_osvdb_id(152469);

  script_name(english:"OracleVM 3.3 / 3.4 : coreutils (OVMSA-2017-0052)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - clean up empty file if cp is failed [Orabug 15973168]

  - pure rebuild to bring back support for
    acl_extended_file_nofollow on x86_64

  - su: deny killing other processes with root privileges
    (CVE-2017-2616)

  - fix the functionality of 'sort -h -k ...' in multi-byte
    locales (#1357979)

  - use correct path to grep(1) in colorls.sh (#1376892)

  - make colorls.sh compatible with ksh (#1321643)

  - sed should actually be /bin/sed (related #1222140)

  - colorls.sh,colorls.csh - call utilities with complete
    path (#1222140)

  - mkdir, mkfifo, mknod - respect default umask/acls when
    COREUTILS_CHILD_DEFAULT_ACLS envvar is set (to match
    rhel 7 behaviour,

  - ls: improve efficiency on filesystems without support
    for ACLs, xattrs or SELinux (#1248141)

  - su: suppress PAM info messages for -c or non-login
    sessions (#1267588)

  - tail, stat: recognize several new filesystems - up2date
    by Jan 1st 2016 (#1280333)

  - du: improve du error message of coreutils commands in a
    chrooted environment (patch by Boris Ranto) (#1086916)

  - su: fix incorrect message printing when su is killed
    (#1147532)"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000662.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40167d41"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-March/000667.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7493a037"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected coreutils / coreutils-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:coreutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:coreutils-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "(3\.3|3\.4)" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3 / 3.4", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"coreutils-8.4-46.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"coreutils-libs-8.4-46.0.1.el6")) flag++;

if (rpm_check(release:"OVS3.4", reference:"coreutils-8.4-46.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.4", reference:"coreutils-libs-8.4-46.0.1.el6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "coreutils / coreutils-libs");
}
