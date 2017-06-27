#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0388. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97511);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/07 17:25:24 $");

  script_cve_id("CVE-2017-2590");
  script_osvdb_id(152644);
  script_xref(name:"RHSA", value:"2017:0388");

  script_name(english:"RHEL 7 : ipa (RHSA-2017:0388)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for ipa is now available for Red Hat Enterprise Linux 7.

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
    value:"https://www.redhat.com/security/data/cve/CVE-2017-2590.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0388.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0388";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL7", reference:"ipa-admintools-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ipa-client-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-client-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ipa-client-common-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ipa-common-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"ipa-debuginfo-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-debuginfo-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ipa-python-compat-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-server-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ipa-server-common-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"ipa-server-dns-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"python2-ipaclient-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"python2-ipalib-4.4.0-14.el7_3.6")) flag++;

  if (rpm_check(release:"RHEL7", reference:"python2-ipaserver-4.4.0-14.el7_3.6")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ipa-admintools / ipa-client / ipa-client-common / ipa-common / etc");
  }
}
