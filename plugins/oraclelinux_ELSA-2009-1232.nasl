#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1232 and 
# Oracle Linux Security Advisory ELSA-2009-1232 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67916);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 16:53:47 $");

  script_cve_id("CVE-2009-2730");
  script_bugtraq_id(35952);
  script_xref(name:"RHSA", value:"2009:1232");

  script_name(english:"Oracle Linux 4 / 5 : gnutls (ELSA-2009-1232)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1232 :

Updated gnutls packages that fix a security issue are now available
for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS).

A flaw was discovered in the way GnuTLS handles NULL characters in
certain fields of X.509 certificates. If an attacker is able to get a
carefully-crafted certificate signed by a Certificate Authority
trusted by an application using GnuTLS, the attacker could use the
certificate during a man-in-the-middle attack and potentially confuse
the application into accepting it by mistake. (CVE-2009-2730)

Users of GnuTLS are advised to upgrade to these updated packages,
which contain a backported patch that corrects this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-August/001131.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-August/001132.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/26");
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
if (rpm_check(release:"EL4", reference:"gnutls-1.0.20-4.0.1.el4_8.3")) flag++;
if (rpm_check(release:"EL4", reference:"gnutls-devel-1.0.20-4.0.1.el4_8.3")) flag++;

if (rpm_check(release:"EL5", reference:"gnutls-1.4.1-3.el5_3.5")) flag++;
if (rpm_check(release:"EL5", reference:"gnutls-devel-1.4.1-3.el5_3.5")) flag++;
if (rpm_check(release:"EL5", reference:"gnutls-utils-1.4.1-3.el5_3.5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-devel / gnutls-utils");
}
