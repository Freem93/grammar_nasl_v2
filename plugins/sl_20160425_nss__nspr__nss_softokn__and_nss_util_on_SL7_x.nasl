#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(90751);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/10/19 14:25:13 $");

  script_cve_id("CVE-2016-1978", "CVE-2016-1979");

  script_name(english:"Scientific Linux Security Update : nss, nspr, nss-softokn, and nss-util on SL7.x x86_64");
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
"The following packages have been upgraded to a newer upstream version:
nss (3.21.0), nss-util (3.21.0), nspr (4.11.0).

Security Fix(es) :

  - A use-after-free flaw was found in the way NSS handled
    DHE (DiffieHellman key exchange) and ECDHE (Elliptic
    Curve Diffie-Hellman key exchange) handshake messages. A
    remote attacker could send a specially crafted handshake
    message that, when parsed by an application linked
    against NSS, would cause that application to crash or,
    under certain special conditions, execute arbitrary code
    using the permissions of the user running the
    application. (CVE-2016-1978)

  - A use-after-free flaw was found in the way NSS processed
    certain DER (Distinguished Encoding Rules) encoded
    cryptographic keys. An attacker could use this flaw to
    create a specially crafted DER encoded certificate
    which, when parsed by an application compiled against
    the NSS library, could cause that application to crash,
    or execute arbitrary code using the permissions of the
    user running the application. (CVE-2016-1979)

Bug Fix(es) :

  - The nss-softokn package has been updated to be
    compatible with NSS 3.21."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1604&L=scientific-linux-errata&F=&S=&P=14559
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75dda98c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nspr-4.11.0-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nspr-debuginfo-4.11.0-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nspr-devel-4.11.0-1.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-3.21.0-9.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-debuginfo-3.21.0-9.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-devel-3.21.0-9.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.21.0-9.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-3.16.2.3-14.2.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-debuginfo-3.16.2.3-14.2.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-devel-3.16.2.3-14.2.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-freebl-3.16.2.3-14.2.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-freebl-devel-3.16.2.3-14.2.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-sysinit-3.21.0-9.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-tools-3.21.0-9.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-3.21.0-2.2.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-debuginfo-3.21.0-2.2.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-devel-3.21.0-2.2.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
