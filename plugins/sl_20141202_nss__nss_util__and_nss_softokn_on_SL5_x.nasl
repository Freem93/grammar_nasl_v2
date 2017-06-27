#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(79713);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/10/19 14:25:12 $");

  script_cve_id("CVE-2014-3566");

  script_name(english:"Scientific Linux Security Update : nss, nss-util, and nss-softokn on SL5.x, SL6.x, SL7.x i386/x86_64 (POODLE)");
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
"This update adds support for the TLS Fallback Signaling Cipher Suite
Value (TLS_FALLBACK_SCSV), which can be used to prevent protocol
downgrade attacks against applications which re-connect using a lower
SSL/TLS protocol version when the initial connection indicating the
highest supported protocol version fails.

This can prevent a forceful downgrade of the communication to SSL 3.0.
The SSL 3.0 protocol was found to be vulnerable to the padding oracle
attack when using block cipher suites in cipher block chaining (CBC)
mode. This issue is identified as CVE-2014-3566, and also known under
the alias POODLE. This SSL 3.0 protocol flaw will not be addressed in
a future update; it is recommended that users configure their
applications to require at least TLS protocol version 1.0 for secure
communication.

The nss, nss-util, and nss-softokn packages have been upgraded to
upstream version 3.16.2.3, which provides a number of bug fixes and
enhancements over the previous version, and adds the support for
Mozilla Firefox 31.3.

After installing this update, applications using NSS or NSPR must be
restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=542
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9cd03081"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"nss-3.16.2.3-1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"nss-debuginfo-3.16.2.3-1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.16.2.3-1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.16.2.3-1.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.16.2.3-1.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"nss-3.16.2.3-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.16.2.3-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.16.2.3-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.16.2.3-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.16.2.3-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.16.2.3-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-3.16.2.3-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-debuginfo-3.16.2.3-2.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"nss-util-devel-3.16.2.3-2.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-3.16.2.3-2.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-debuginfo-3.16.2.3-2.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-devel-3.16.2.3-2.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-pkcs11-devel-3.16.2.3-2.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-3.16.2.3-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-debuginfo-3.16.2.3-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-devel-3.16.2.3-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-freebl-3.16.2.3-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-softokn-freebl-devel-3.16.2.3-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-sysinit-3.16.2.3-2.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-tools-3.16.2.3-2.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-3.16.2.3-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-debuginfo-3.16.2.3-1.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nss-util-devel-3.16.2.3-1.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
