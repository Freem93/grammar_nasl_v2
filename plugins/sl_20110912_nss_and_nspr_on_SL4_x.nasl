#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61133);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_name(english:"Scientific Linux Security Update : nss and nspr on SL4.x, SL5.x, SL6.x i386/x86_64");
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
"Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications.

Netscape Portable Runtime (NSPR) provides platform independence for
non-GUI operating system facilities.

It was found that a Certificate Authority (CA) issued fraudulent HTTPS
certificates. This update renders any HTTPS certificates signed by
that CA as untrusted. This covers all uses of the certificates,
including SSL, S/MIME, and code signing. Note: This fix only applies
to applications using the NSS Builtin Object Token. It does not render
the certificates untrusted for applications that use the NSS library,
but do not use the NSS Builtin Object Token.

These updated packages upgrade NSS to version 3.12.10 on Scientific
Linux 4 and 5. As well, they upgrade NSPR to version 4.8.8 on
Scientific Linux 4 and 5, as required by the NSS update. The packages
for Scientific Linux 6 include a backported patch.

All NSS and NSPR users should upgrade to these updated packages, which
correct this issue. After installing the update, applications using
NSS and NSPR must be restarted for the changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1109&L=scientific-linux-errata&T=0&P=1822
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?666e592f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"nspr-4.8.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nspr-debuginfo-4.8.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nspr-devel-4.8.8-1.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-3.12.10-4.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-debuginfo-3.12.10-4.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-devel-3.12.10-4.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-tools-3.12.10-4.el4")) flag++;

if (rpm_check(release:"SL5", reference:"nspr-4.8.8-1.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-debuginfo-4.8.8-1.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-devel-4.8.8-1.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nss-3.12.10-4.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nss-debuginfo-3.12.10-4.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.12.10-4.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.12.10-4.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.12.10-4.el5_7")) flag++;

if (rpm_check(release:"SL6", reference:"nss-3.12.9-12.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.12.9-12.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.12.9-12.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.12.9-12.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-3.12.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-devel-3.12.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-freebl-3.12.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-softokn-freebl-devel-3.12.9-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.12.9-12.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.12.9-12.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.12.9-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.12.9-1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
