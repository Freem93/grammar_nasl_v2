#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(85205);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/04 14:00:09 $");

  script_cve_id("CVE-2012-2662");

  script_name(english:"Scientific Linux Security Update : pki-core on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple cross-site scripting flaws were discovered in the Red Hat
Certificate System Agent and End Entity pages. An attacker could use
these flaws to perform a cross-site scripting (XSS) attack against
victims using the Certificate System's web interface. (CVE-2012-2662)

This update also fixes the following bugs :

  - Previously, pki-core required the SSL version 3 (SSLv3)
    protocol ranges to communicate with the 389-ds-base
    packages. However, recent changes to 389-ds-base
    disabled the default use of SSLv3 and enforced using
    protocol ranges supported by secure protocols, such as
    the TLS protocol. As a consequence, the CA failed to
    install during an Identity Management (IdM) server
    installation. This update adds TLS-related parameters to
    the server.xml file of the CA to fix this problem, and
    running the ipa-server- install command now installs the
    CA as expected.

  - Previously, the ipa-server-install script failed when
    attempting to configure a stand-alone CA on systems with
    OpenJDK version 1.8.0 installed. The pki-core build and
    runtime dependencies have been modified to use OpenJDK
    version 1.7.0 during the stand-alone CA configuration.
    As a result, ipa-server-install no longer fails in this
    situation.

  - Creating a Scientific Linux 7 replica from a Scientific
    Linux 6 replica running the CA service sometimes failed
    in IdM deployments where the initial Scientific Linux 6
    CA master had been removed. This could cause problems in
    some situations, such as when migrating from Scientific
    Linux 6 to Scientific Linux 7. The bug occurred due to a
    problem in a previous version of IdM where the subsystem
    user, created during the initial CA server installation,
    was removed together with the initial master. This
    update adds the restore-subsystem-user.py script that
    restores the subsystem user in the described situation,
    thus enabling administrators to create a Scientific
    Linux 7 replica in this scenario.

  - Several Java import statements specify wildcard
    arguments. However, due to the use of wildcard arguments
    in the import statements of the source code contained in
    the Scientific Linux 6 maintenance branch, a name space
    collision created the potential for an incorrect class
    to be utilized. As a consequence, the Token Processing
    System (TPS) rebuild test failed with an error message.
    This update addresses the bug by supplying the fully
    named class in all of the affected areas, and the TPS
    rebuild test no longer fails.

  - Previously, pki-core failed to build with the rebased
    version of the CMake build system during the TPS rebuild
    test. The pki-core build files have been updated to
    comply with the rebased version of CMake. As a result,
    pki-core builds successfully in the described scenario."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=5148
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f3a87c1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"pki-ca-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-common-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-common-javadoc-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-core-debuginfo-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-java-tools-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-java-tools-javadoc-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-native-tools-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-selinux-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-setup-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-silent-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-symkey-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-util-9.0.3-43.el6")) flag++;
if (rpm_check(release:"SL6", reference:"pki-util-javadoc-9.0.3-43.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
