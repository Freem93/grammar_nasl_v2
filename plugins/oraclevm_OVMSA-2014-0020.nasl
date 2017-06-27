#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2014-0020.
#

include("compat.inc");

if (description)
{
  script_id(78236);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/14 17:16:23 $");

  script_name(english:"OracleVM 2.2 : bash (OVMSA-2014-0020)");
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

  - Check for fishy environment Resolves: #1141644

  - Fixed a bug that caused trap handlers to be executed
    recursively, corrupting internal data structures.
    Resolves: #964753

  - Don't include backup files Resolves: #700157

  - Use `mktemp' for temporary files Resolves: #700157

  - Added man page references to systemwide .bash_logout
    Resolves: #592979

  - Readline glitch, when editing line with more spaces and
    resizing window Resolves: #525474

  - Fix the memory leak in read builtin Resolves: #618393

  - Don't append slash to non-directories Resolves: #583919

  - Test .dynamic section if has PROGBITS or NOBITS
    Resolves: #484809

  - Better random number generator Resolves: #492908

  - Allow to source scripts with embeded NULL chars
    Resolves: #503701

  - vi mode redo insert fixed Resolves: #575076

  - Don't show broken pipe messages for builtins Resolves:
    #546529

  - Don't include loadables in doc dir Resolves: #663656

  - Enable system-wide .bash_logout for login shells
    Resolves: #592979

  - Don't abort source builtin Resolves: #448508

  - Correctly place cursor Resolves: #463880

  - Minor man page clarification for trap builtin Resolves:
    #504904"
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2014-September/000221.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d09838a9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected bash package.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:bash");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "2\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.2", reference:"bash-3.2-33.el5.1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash");
}
