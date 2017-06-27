#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61175);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_name(english:"Scientific Linux Security Update : nss on SL4.x, SL5.x, SL6.x i386/x86_64");
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
support the development of security-enabled client and server
applications.

It was found that the Malaysia-based Digicert Sdn. Bhd. subordinate
Certificate Authority (CA) issued HTTPS certificates with weak keys.
This update renders any HTTPS certificates signed by that CA as
untrusted. This covers all uses of the certificates, including SSL,
S/MIME, and code signing. Note: Digicert Sdn. Bhd. is not the same
company as found at digicert.com.

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not render the certificates untrusted for
applications that use the NSS library, but do not use the NSS Builtin
Object Token.

This update also fixes the following bug on Scientific Linux 5 :

  - When using mod_nss with the Apache HTTP Server, a bug in
    NSS on Scientific Linux 5 resulted in file descriptors
    leaking each time the Apache HTTP Server was restarted
    with the 'service httpd reload' command. This could have
    prevented the Apache HTTP Server from functioning
    properly if all available file descriptors were
    consumed.

For Scientific Linux 6, these updated packages upgrade NSS to version
3.12.10. As well, they upgrade NSPR (Netscape Portable Runtime) to
version 4.8.8 and nss-util to version 3.12.10 on Scientific Linux 6,
as required by the NSS update.

All NSS users should upgrade to these updated packages, which correct
this issue. After installing the update, applications using NSS must
be restarted for the changes to take effect. In addition, on
Scientific Linux 6, applications using NSPR and nss-util must also be
restarted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1111&L=scientific-linux-errata&T=0&P=1744
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c02cd02"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/09");
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
if (rpm_check(release:"SL4", reference:"nss-3.12.10-6.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-debuginfo-3.12.10-6.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-devel-3.12.10-6.el4")) flag++;
if (rpm_check(release:"SL4", reference:"nss-tools-3.12.10-6.el4")) flag++;

if (rpm_check(release:"SL5", reference:"nss-3.12.10-7.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nss-debuginfo-3.12.10-7.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.12.10-7.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.12.10-7.el5_7")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.12.10-7.el5_7")) flag++;

if (rpm_check(release:"SL6", reference:"nspr-4.8.8-1.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-debuginfo-4.8.8-1.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nspr-devel-4.8.8-1.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-3.12.10-2.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.12.10-2.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.12.10-2.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.12.10-2.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.12.10-2.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.12.10-2.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.12.10-1.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.12.10-1.el6_1")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.12.10-1.el6_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
