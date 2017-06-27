#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0181 and 
# Oracle Linux Security Advisory ELSA-2008-0181 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67669);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/07 20:57:49 $");

  script_cve_id("CVE-2008-0062", "CVE-2008-0063", "CVE-2008-0947", "CVE-2008-0948");
  script_bugtraq_id(28302, 28303);
  script_osvdb_id(43341, 43342, 43343, 43344);
  script_xref(name:"RHSA", value:"2008:0181");

  script_name(english:"Oracle Linux 3 : krb5 (ELSA-2008-0181)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0181 :

Updated krb5 packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 2.1 and 3.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Kerberos is a network authentication system which allows clients and
servers to authenticate to each other through use of symmetric
encryption and a trusted third party, the KDC.

A flaw was found in the way the MIT Kerberos Authentication Service
and Key Distribution Center server (krb5kdc) handled Kerberos v4
protocol packets. An unauthenticated remote attacker could use this
flaw to crash the krb5kdc daemon, disclose portions of its memory, or
possibly execute arbitrary code using malformed or truncated Kerberos
v4 protocol requests. (CVE-2008-0062, CVE-2008-0063)

This issue only affected krb5kdc with Kerberos v4 protocol
compatibility enabled, which is the default setting on Red Hat
Enterprise Linux 4. Kerberos v4 protocol support can be disabled by
adding 'v4_mode=none' (without the quotes) to the '[kdcdefaults]'
section of /var/kerberos/krb5kdc/kdc.conf.

A flaw was found in the RPC library used by the MIT Kerberos kadmind
server. An unauthenticated remote attacker could use this flaw to
crash kadmind. This issue only affected systems with certain resource
limits configured and did not affect systems using default resource
limits used by Red Hat Enterprise Linux 2.1 or 3. (CVE-2008-0948)

Red Hat would like to thank MIT for reporting these issues.

All krb5 users are advised to update to these erratum packages which
contain backported fixes to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-March/000545.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected krb5 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/18");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 3", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-devel-1.2.7-68")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-devel-1.2.7-68")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-libs-1.2.7-68")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-libs-1.2.7-68")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-server-1.2.7-68")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-server-1.2.7-68")) flag++;
if (rpm_check(release:"EL3", cpu:"i386", reference:"krb5-workstation-1.2.7-68")) flag++;
if (rpm_check(release:"EL3", cpu:"x86_64", reference:"krb5-workstation-1.2.7-68")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "krb5-devel / krb5-libs / krb5-server / krb5-workstation");
}
