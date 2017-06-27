#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0388 and 
# CentOS Errata and Security Advisory 2017:0388 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(97527);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/06 14:38:27 $");

  script_cve_id("CVE-2017-2590");
  script_osvdb_id(152644);
  script_xref(name:"RHSA", value:"2017:0388");

  script_name(english:"CentOS 7 : ipa (CESA-2017:0388)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2017-March/022310.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fc52c91"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ipa packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-admintools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-python-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python2-ipaserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-admintools-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-client-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-client-common-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-common-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-python-compat-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-common-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-dns-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python2-ipaclient-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python2-ipalib-4.4.0-14.el7.centos.6")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python2-ipaserver-4.4.0-14.el7.centos.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
