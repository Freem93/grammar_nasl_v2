#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0165 and 
# Oracle Linux Security Advisory ELSA-2010-0165 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68019);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/27 14:13:22 $");

  script_cve_id("CVE-2009-3555");
  script_osvdb_id(61234, 62064);
  script_xref(name:"RHSA", value:"2010:0165");

  script_name(english:"Oracle Linux 4 / 5 : nss (ELSA-2010-0165)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0165 :

Updated nss packages that fix a security issue are now available for
Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Applications built with NSS can support SSLv2,
SSLv3, TLS, and other security standards.

Netscape Portable Runtime (NSPR) provides platform independence for
non-GUI operating system facilities. These facilities include threads,
thread synchronization, normal file and network I/O, interval timing,
calendar time, basic memory management (malloc and free), and shared
library linking.

A flaw was found in the way the TLS/SSL (Transport Layer
Security/Secure Sockets Layer) protocols handled session
renegotiation. A man-in-the-middle attacker could use this flaw to
prefix arbitrary plain text to a client's session (for example, an
HTTPS connection to a website). This could force the server to process
an attacker's request as if authenticated using the victim's
credentials. This update addresses this flaw by implementing the TLS
Renegotiation Indication Extension, as defined in RFC 5746.
(CVE-2009-3555)

Refer to the following Knowledgebase article for additional details
about this flaw: http://kbase.redhat.com/faq/docs/DOC-20491

Users of Red Hat Certificate System 7.3 and 8.0 should review the
following Knowledgebase article before installing this update:
http://kbase.redhat.com/faq/docs/DOC-28439

All users of NSS are advised to upgrade to these updated packages,
which update NSS to version 3.12.6. This erratum also updates the NSPR
packages to the version required by NSS 3.12.6. All running
applications using the NSS library must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-March/001402.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-March/001411.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected nss packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"nspr-4.8.4-1.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"nspr-devel-4.8.4-1.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"nss-3.12.6-1.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"nss-devel-3.12.6-1.0.1.el4_8")) flag++;
if (rpm_check(release:"EL4", reference:"nss-tools-3.12.6-1.0.1.el4_8")) flag++;

if (rpm_check(release:"EL5", reference:"nspr-4.8.4-1.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"nspr-devel-4.8.4-1.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"nss-3.12.6-1.0.1.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"nss-devel-3.12.6-1.0.1.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"nss-pkcs11-devel-3.12.6-1.0.1.el5_4")) flag++;
if (rpm_check(release:"EL5", reference:"nss-tools-3.12.6-1.0.1.el5_4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nspr / nspr-devel / nss / nss-devel / nss-pkcs11-devel / nss-tools");
}
