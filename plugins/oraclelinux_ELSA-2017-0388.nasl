#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2017:0388 and 
# Oracle Linux Security Advisory ELSA-2017-0388 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(97507);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_cve_id("CVE-2017-2590");
  script_osvdb_id(152644);
  script_xref(name:"RHSA", value:"2017:0388");

  script_name(english:"Oracle Linux 7 : ipa (ELSA-2017-0388)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2017:0388 :

An update for ipa is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Red Hat Identity Management (IdM) is a centralized authentication,
identity management, and authorization solution for both traditional
and cloud-based enterprise environments.

Security Fix(es) :

* It was found that IdM's ca-del, ca-disable, and ca-enable commands
did not properly check the user's permissions while modifying CAs in
Dogtag. An authenticated, unauthorized attacker could use this flaw to
delete, disable, or enable CAs causing various denial of service
problems with certificate issuance, OCSP signing, and deletion of
secret keys. (CVE-2017-2590)

This issue was discovered by Fraser Tweedale (Red Hat).

Bug Fix(es) :

* Previously, during an Identity Management (IdM) replica installation
that runs on domain level '1' or higher, Directory Server was not
configured to use TLS encryption. As a consequence, installing a
certificate authority (CA) on that replica failed. Directory Server is
now configured to use TLS encryption during the replica installation
and as a result, the CA installation works as expected. (BZ#1410760)

* Previously, the Identity Management (IdM) public key infrastructure
(PKI) component was configured to listen on the '::1' IPv6 localhost
address. In environments have the the IPv6 protocol disabled, the
replica installer was unable to retrieve the Directory Server
certificate, and the installation failed. The default listening
address of the PKI connector has been updated from the IP address to
'localhost'. As a result, the PKI connector now listens on the correct
addresses in IPv4 and IPv6 environments. (BZ#1416481)

* Previously, when installing a certificate authority (CA) on a
replica, Identity Management (IdM) was unable to provide third-party
CA certificates to the Certificate System CA installer. As a
consequence, the installer was unable to connect to the remote master
if the remote master used a third-party server certificate, and the
installation failed. This updates applies a patch and as a result,
installing a CA replica works as expected in the described situation.
(BZ#1415158)

* When installing a replica, the web server service entry is created
on the Identity Management (IdM) master and replicated to all IdM
servers. Previously, when installing a replica without a certificate
authority (CA), in certain situations the service entry was not
replicated to the new replica on time, and the installation failed.
The replica installer has been updated and now waits until the web
server service entry is replicated. As a result, the replica
installation no longer fails in the described situation. (BZ#1416488)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2017-March/006746.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-admintools-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-client-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-client-common-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-common-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-python-compat-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-server-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-server-common-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-server-dns-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python2-ipaclient-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python2-ipalib-4.4.0-14.0.1.el7_3.6")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"python2-ipaserver-4.4.0-14.0.1.el7_3.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-client-common / ipa-common / etc");
}
