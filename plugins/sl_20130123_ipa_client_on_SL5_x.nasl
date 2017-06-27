#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64090);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/01/31 11:57:27 $");

  script_cve_id("CVE-2012-5484");

  script_name(english:"Scientific Linux Security Update : ipa-client on SL5.x i386/x86_64");
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
"A weakness was found in the way IPA clients communicated with IPA
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

When a fix for this flaw has been applied to the client but not yet
the server, ipa-client-install, in unattended mode, will fail if you
do not have the correct CA certificate locally, noting that you must
use the '--force' option to insecurely obtain the certificate. In
interactive mode, the certificate will try to be obtained securely
from LDAP. If this fails, you will be prompted to insecurely download
the certificate via HTTP. In the same situation when using OTP, LDAP
will not be queried and you will be prompted to insecurely download
the certificate via HTTP."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=3332
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdbe06ed"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"authconfig-5.3.21-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"authconfig-gtk-5.3.21-7.el5")) flag++;
if (rpm_check(release:"SL5", reference:"certmonger-0.50-3.el5")) flag++;
if (rpm_check(release:"SL5", reference:"curl-7.15.5-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"curl-devel-7.15.5-15.el5")) flag++;
if (rpm_check(release:"SL5", reference:"ipa-client-2.1.3-5.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"ipa-client-debuginfo-2.1.3-5.el5_9.2")) flag++;
if (rpm_check(release:"SL5", reference:"libipa_hbac-1.5.1-58.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libipa_hbac-devel-1.5.1-58.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libipa_hbac-python-1.5.1-58.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libtdb-1.2.10-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"libtdb-devel-1.2.10-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"policycoreutils-1.33.12-14.8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"policycoreutils-gui-1.33.12-14.8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"policycoreutils-newrole-1.33.12-14.8.el5")) flag++;
if (rpm_check(release:"SL5", reference:"shadow-utils-4.0.17-21.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sssd-1.5.1-58.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sssd-client-1.5.1-58.el5")) flag++;
if (rpm_check(release:"SL5", reference:"sssd-tools-1.5.1-58.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xmlrpc-c-1.16.24-1206.1840.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xmlrpc-c-apps-1.16.24-1206.1840.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xmlrpc-c-c++-1.16.24-1206.1840.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xmlrpc-c-client-1.16.24-1206.1840.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xmlrpc-c-client++-1.16.24-1206.1840.4.el5")) flag++;
if (rpm_check(release:"SL5", reference:"xmlrpc-c-devel-1.16.24-1206.1840.4.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
