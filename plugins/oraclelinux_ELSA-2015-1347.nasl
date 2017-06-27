#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1347 and 
# Oracle Linux Security Advisory ELSA-2015-1347 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85101);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2015/12/04 14:37:59 $");

  script_cve_id("CVE-2012-2662");
  script_bugtraq_id(54608);
  script_osvdb_id(84099);
  script_xref(name:"RHSA", value:"2015:1347");

  script_name(english:"Oracle Linux 6 : pki-core (ELSA-2015-1347)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2015:1347 :

Updated pki-core packages that fix one security issue and several bugs
are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Red Hat Certificate System is an enterprise software system designed
to manage enterprise public key infrastructure (PKI) deployments. PKI
Core contains fundamental packages required by Red Hat Certificate
System, which comprise the Certificate Authority (CA) subsystem.

Multiple cross-site scripting flaws were discovered in the Red Hat
Certificate System Agent and End Entity pages. An attacker could use
these flaws to perform a cross-site scripting (XSS) attack against
victims using the Certificate System's web interface. (CVE-2012-2662)

This update also fixes the following bugs :

* Previously, pki-core required the SSL version 3 (SSLv3) protocol
ranges to communicate with the 389-ds-base packages. However, recent
changes to 389-ds-base disabled the default use of SSLv3 and enforced
using protocol ranges supported by secure protocols, such as the TLS
protocol. As a consequence, the CA failed to install during an
Identity Management (IdM) server installation. This update adds
TLS-related parameters to the server.xml file of the CA to fix this
problem, and running the ipa-server-install command now installs the
CA as expected. (BZ#1171848)

* Previously, the ipa-server-install script failed when attempting to
configure a stand-alone CA on systems with OpenJDK version 1.8.0
installed. The pki-core build and runtime dependencies have been
modified to use OpenJDK version 1.7.0 during the stand-alone CA
configuration. As a result, ipa-server-install no longer fails in this
situation. (BZ#1212557)

* Creating a Red Hat Enterprise Linux 7 replica from a Red Hat
Enterprise Linux 6 replica running the CA service sometimes failed in
IdM deployments where the initial Red Hat Enterprise Linux 6 CA master
had been removed. This could cause problems in some situations, such
as when migrating from Red Hat Enterprise Linux 6 to Red Hat
Enterprise Linux 7. The bug occurred due to a problem in a previous
version of IdM where the subsystem user, created during the initial CA
server installation, was removed together with the initial master.
This update adds the restore-subsystem-user.py script that restores
the subsystem user in the described situation, thus enabling
administrators to create a Red Hat Enterprise Linux 7 replica in this
scenario. (BZ#1225589)

* Several Java import statements specify wildcard arguments. However,
due to the use of wildcard arguments in the import statements of the
source code contained in the Red Hat Enterprise Linux 6 maintenance
branch, a name space collision created the potential for an incorrect
class to be utilized. As a consequence, the Token Processing System
(TPS) rebuild test failed with an error message. This update addresses
the bug by supplying the fully named class in all of the affected
areas, and the TPS rebuild test no longer fails. (BZ#1144188)

* Previously, pki-core failed to build with the rebased version of the
CMake build system during the TPS rebuild test. The pki-core build
files have been updated to comply with the rebased version of CMake.
As a result, pki-core builds successfully in the described scenario.
(BZ#1144608)

Users of pki-core are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2015-July/005231.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pki-core packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-common-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-java-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-java-tools-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-native-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-setup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-silent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-symkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pki-util-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"pki-ca-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-common-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-common-javadoc-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-java-tools-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-java-tools-javadoc-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-native-tools-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-selinux-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-setup-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-silent-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-symkey-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-util-9.0.3-43.el6")) flag++;
if (rpm_check(release:"EL6", reference:"pki-util-javadoc-9.0.3-43.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pki-ca / pki-common / pki-common-javadoc / pki-java-tools / etc");
}
