#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(64428);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/02/04 00:42:19 $");

  script_name(english:"Scientific Linux Security Update : nss and nspr on SL5.x i386/x86_64");
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
"It was found that a Certificate Authority (CA) mis-issued two
intermediate certificates to customers. These certificates could be
used to launch man-in- the-middle attacks. This update renders those
certificates as untrusted. This covers all uses of the certificates,
including SSL, S/MIME, and code signing.

In addition, the nss package has been upgraded to upstream version
3.13.6, and the nspr package has been upgraded to upstream version
4.9.2. These updates provide a number of bug fixes and enhancements
over the previous versions.

After installing the update, applications using NSS and NSPR must be
restarted for the changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=602
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71fd6886"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/03");
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
if (rpm_check(release:"SL5", reference:"nspr-4.9.2-2.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-debuginfo-4.9.2-2.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nspr-devel-4.9.2-2.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nss-3.13.6-3.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nss-debuginfo-3.13.6-3.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.13.6-3.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.13.6-3.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.13.6-3.el5_9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
