#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2016-0079.
#

include("compat.inc");

if (description)
{
  script_id(91755);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/14 17:23:20 $");

  script_cve_id("CVE-2013-1775", "CVE-2013-1776", "CVE-2013-2776", "CVE-2013-2777", "CVE-2014-0106");
  script_bugtraq_id(58203, 58207, 62741, 65997);
  script_osvdb_id(90661, 90677, 104086);

  script_name(english:"OracleVM 3.2 : sudo (OVMSA-2016-0079)");
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

  - added patch for CVE-2014-0106: certain environment
    variables not sanitized when env_reset is disabled
    Resolves: rhbz#1072210

  - backported fixes for CVE-2013-1775 CVE-2013-1776
    (CVE-2013-2776) CVE-2013-2777 Resolves: rhbz#968221

  - visudo: fixed incorrect warning and parse error
    regarding undefined aliases which were in fact defined
    Resolves: rhbz#849679 Resolves: rhbz#905624

  - updated sudoers man-page to clarify the behavior of the
    user negation operator and the behavior of wildcard
    matching in command specifications Resolves: rhbz#846118
    Resolves: rhbz#856902

  - fixed regression in escaping of sudo -i arguments
    Resolves: rhbz#853203

  - bump release number

  - Fixed caching of user and group names

  - Backported RFC 4515 escaping of LDAP queries Resolves:
    rhbz#855836 Resolves: rhbz#869287

  - Add the -c option to sed commands in post/postun scripts
    Resolves: rhbz#818585

  - Implement a new sudoers Defaults option to restore old
    command exec behavior Resolves: rhbz#840971

  - Add ability to treat files authoritatively in
    sudoers.ldap Resolves: rhbz#840097

  - Changed policycoreutils dependency to a context specific
    dependency (post & postun) Resolves: rhbz#846694

  - don't use a temporary file when modifying nsswitch.conf

  - fix permissions on nsswitch.conf, if needed Resolves:
    rhbz#846631

  - added a workaround for a race condition in handling
    child processes Resolves: rhbz#829263

  - use safe temporary files in post/postun scripts

  - corrected postun script Resolves: rhbz#841070

  - corrected release number

  - call restorecon after modifying nsswitch.conf in the
    postun scriplet

  - added policycoreutils dependency Resolves: rhbz#818585

  - fixed `sudo -i' command escaping (#806073)

  - fixed multiple sudoHost LDAP attr. handlng (#740884)
    Resolves: rhbz#740884 Resolves: rhbz#806073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2016-June/000493.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Sudo Password Bypass');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "3\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.2", reference:"sudo-1.7.2p1-29.el5_10")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "sudo");
}
