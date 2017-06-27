#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2140 and 
# Oracle Linux Security Advisory ELSA-2015-2140 respectively.
#

include("compat.inc");

if (description)
{
  script_id(87024);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/28 19:11:31 $");

  script_cve_id("CVE-2015-1782");
  script_osvdb_id(119444);
  script_xref(name:"RHSA", value:"2015:2140");

  script_name(english:"Oracle Linux 7 : libssh2 (ELSA-2015-2140)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:2140 :

Updated libssh2 packages that fix one security issue and two bugs are
now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The libssh2 packages provide a library that implements the SSH2
protocol.

A flaw was found in the way the kex_agree_methods() function of
libssh2 performed a key exchange when negotiating a new SSH session. A
man-in-the-middle attacker could use a crafted SSH_MSG_KEXINIT packet
to crash a connecting libssh2 client. (CVE-2015-1782)

This update also fixes the following bugs :

* Previously, libssh2 did not correctly adjust the size of the receive
window while reading from an SSH channel. This caused downloads over
the secure copy (SCP) protocol to consume an excessive amount of
memory. A series of upstream patches has been applied on the libssh2
source code to improve handling of the receive window size. Now, SCP
downloads work as expected. (BZ#1080459)

* Prior to this update, libssh2 did not properly initialize an
internal variable holding the SSH agent file descriptor, which caused
the agent destructor to close the standard input file descriptor by
mistake. An upstream patch has been applied on libssh2 sources to
properly initialize the internal variable. Now, libssh2 closes only
the file descriptors it owns. (BZ#1147717)

All libssh2 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. After
installing these updated packages, all running applications using
libssh2 must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-November/005554.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssh2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libssh2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libssh2-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libssh2-1.4.3-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libssh2-devel-1.4.3-10.el7")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"libssh2-docs-1.4.3-10.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssh2 / libssh2-devel / libssh2-docs");
}
