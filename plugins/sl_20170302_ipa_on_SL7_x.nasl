#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(97515);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/03 14:52:26 $");

  script_cve_id("CVE-2017-2590");

  script_name(english:"Scientific Linux Security Update : ipa on SL7.x x86_64");
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
"Security Fix(es) :

  - It was found that IdM's ca-del, ca-disable, and
    ca-enable commands did not properly check the user's
    permissions while modifying CAs in Dogtag. An
    authenticated, unauthorized attacker could use this flaw
    to delete, disable, or enable CAs causing various denial
    of service problems with certificate issuance, OCSP
    signing, and deletion of secret keys. (CVE-2017-2590)

Bug Fix(es) :

  - Previously, during an Identity Management (IdM) replica
    installation that runs on domain level '1' or higher,
    Directory Server was not configured to use TLS
    encryption. As a consequence, installing a certificate
    authority (CA) on that replica failed. Directory Server
    is now configured to use TLS encryption during the
    replica installation and as a result, the CA
    installation works as expected.

  - Previously, the Identity Management (IdM) public key
    infrastructure (PKI) component was configured to listen
    on the '::1' IPv6 localhost address. In environments
    have the the IPv6 protocol disabled, the replica
    installer was unable to retrieve the Directory Server
    certificate, and the installation failed. The default
    listening address of the PKI connector has been updated
    from the IP address to 'localhost'. As a result, the PKI
    connector now listens on the correct addresses in IPv4
    and IPv6 environments.

  - Previously, when installing a certificate authority (CA)
    on a replica, Identity Management (IdM) was unable to
    provide third-party CA certificates to the Certificate
    System CA installer. As a consequence, the installer was
    unable to connect to the remote master if the remote
    master used a third-party server certificate, and the
    installation failed. This updates applies a patch and as
    a result, installing a CA replica works as expected in
    the described situation.

  - When installing a replica, the web server service entry
    is created on the Identity Management (IdM) master and
    replicated to all IdM servers. Previously, when
    installing a replica without a certificate authority
    (CA), in certain situations the service entry was not
    replicated to the new replica on time, and the
    installation failed. The replica installer has been
    updated and now waits until the web server service entry
    is replicated. As a result, the replica installation no
    longer fails in the described situation."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1703&L=scientific-linux-errata&F=&S=&P=1161
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d56d7364"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", reference:"ipa-admintools-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-client-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-client-common-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-common-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-debuginfo-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-python-compat-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-server-common-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"ipa-server-dns-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ipa-server-trust-ad-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipaclient-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipalib-4.4.0-14.el7_3.6")) flag++;
if (rpm_check(release:"SL7", reference:"python2-ipaserver-4.4.0-14.el7_3.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
