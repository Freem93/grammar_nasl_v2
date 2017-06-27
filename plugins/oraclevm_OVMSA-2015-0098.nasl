#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0098.
#

include("compat.inc");

if (description)
{
  script_id(85139);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2013-1752", "CVE-2014-7185");
  script_bugtraq_id(63804, 70089);
  script_osvdb_id(101381, 101382, 101383, 101384, 101385, 101386, 112028);

  script_name(english:"OracleVM 3.3 : python (OVMSA-2015-0098)");
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

  - Add Oracle Linux distribution in platform.py [orabug
    21288328] (Keshav Sharma)

  - Enable use of deepcopy with instance methods Resolves:
    rhbz#1223037

  - Since -libs now provide python-ordered dict, added
    ordereddict dist-info to site-packages Resolves:
    rhbz#1199997

  - Fix CVE-2014-7185/4650/1912 (CVE-2013-1752) Resolves:
    rhbz#1206572

  - Fix logging module error when multiprocessing module is
    not initialized Resolves: rhbz#1204966

  - Add provides for python-ordereddict Resolves:
    rhbz#1199997

  - Let ConfigParse handle options without values

  - Add check phase to specfile, fix and skip relevant
    failing tests Resolves: rhbz#1031709

  - Make Popen.communicate catch EINTR error Resolves:
    rhbz#1073165

  - Add choices for sort option of cProfile for better
    output Resolves: rhbz#1160640

  - Make multiprocessing ignore EINTR Resolves: rhbz#1180864

  - Fix iteration over files with very long lines Resolves:
    rhbz#794632

  - Fix subprocess.Popen.communicate being broken by SIGCHLD
    handler. Resolves: rhbz#1065537

  - Rebuild against latest valgrind-devel. Resolves:
    rhbz#1142170

  - Bump release up to ensure proper upgrade path. Related:
    rhbz#958256

  - Fix multilib dependencies. Resolves: rhbz#958256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-July/000346.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python / python-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:python-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/31");
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
if (rpm_check(release:"OVS3.3", reference:"python-2.6.6-64.0.1.el6")) flag++;
if (rpm_check(release:"OVS3.3", reference:"python-libs-2.6.6-64.0.1.el6")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-libs");
}
