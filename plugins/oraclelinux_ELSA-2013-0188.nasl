#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0188 and 
# Oracle Linux Security Advisory ELSA-2013-0188 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68714);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/26 16:04:32 $");

  script_cve_id("CVE-2012-5484");
  script_bugtraq_id(57529);
  script_osvdb_id(89537);
  script_xref(name:"RHSA", value:"2013:0188");

  script_name(english:"Oracle Linux 6 : ipa (ELSA-2013-0188)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2013:0188 :

Updated ipa packages that fix one security issue are now available for
Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Red Hat Identity Management is a centralized authentication, identity
management and authorization solution for both traditional and
cloud-based enterprise environments.

A weakness was found in the way IPA clients communicated with IPA
servers when initially attempting to join IPA domains. As there was no
secure way to provide the IPA server's Certificate Authority (CA)
certificate to the client during a join, the IPA client enrollment
process was susceptible to man-in-the-middle attacks. This flaw could
allow an attacker to obtain access to the IPA server using the
credentials provided by an IPA client, including administrative access
to the entire domain if the join was performed using an
administrator's credentials. (CVE-2012-5484)

Note: This weakness was only exposed during the initial client join to
the realm, because the IPA client did not yet have the CA certificate
of the server. Once an IPA client has joined the realm and has
obtained the CA certificate of the IPA server, all further
communication is secure. If a client were using the OTP (one-time
password) method to join to the realm, an attacker could only obtain
unprivileged access to the server (enough to only join the realm).

Red Hat would like to thank Petr Mensik for reporting this issue.

This update must be installed on both the IPA client and IPA server.
When this update has been applied to the client but not the server,
ipa-client-install, in unattended mode, will fail if you do not have
the correct CA certificate locally, noting that you must use the
'--force' option to insecurely obtain the certificate. In interactive
mode, the certificate will try to be obtained securely from LDAP. If
this fails, you will be prompted to insecurely download the
certificate via HTTP. In the same situation when using OTP, LDAP will
not be queried and you will be prompted to insecurely download the
certificate via HTTP.

Users of ipa are advised to upgrade to these updated packages, which
correct this issue. After installing the update, changes in LDAP are
handled by ipa-ldap-updater automatically and are effective
immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2013-January/003224.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-selinux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"ipa-admintools-2.2.0-17.el6_3.1")) flag++;
if (rpm_check(release:"EL6", reference:"ipa-client-2.2.0-17.el6_3.1")) flag++;
if (rpm_check(release:"EL6", reference:"ipa-python-2.2.0-17.el6_3.1")) flag++;
if (rpm_check(release:"EL6", reference:"ipa-server-2.2.0-17.el6_3.1")) flag++;
if (rpm_check(release:"EL6", reference:"ipa-server-selinux-2.2.0-17.el6_3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-python / ipa-server / etc");
}
