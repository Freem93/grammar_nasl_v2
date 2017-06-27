#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(71641);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/12/27 15:26:09 $");

  script_name(english:"Scientific Linux Security Update : nss on SL5.x, SL6.x i386/x86_64");
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
"It was found that a subordinate Certificate Authority (CA) mis-issued
an intermediate certificate, which could be used to conduct
man-in-the-middle attacks. This update renders that particular
intermediate certificate as untrusted.

Note: This fix only applies to applications using the NSS Builtin
Object Token. It does not render the certificates untrusted for
applications that use the NSS library, but do not use the NSS Builtin
Object Token.

After installing the update, applications using NSS must be restarted
for the changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=5851
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78b14a83"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/27");
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
if (rpm_check(release:"SL5", reference:"nss-3.15.3-4.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nss-debuginfo-3.15.3-4.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nss-devel-3.15.3-4.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nss-pkcs11-devel-3.15.3-4.el5_10")) flag++;
if (rpm_check(release:"SL5", reference:"nss-tools-3.15.3-4.el5_10")) flag++;

if (rpm_check(release:"SL6", reference:"nss-3.15.3-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-debuginfo-3.15.3-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-devel-3.15.3-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-pkcs11-devel-3.15.3-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-sysinit-3.15.3-3.el6_5")) flag++;
if (rpm_check(release:"SL6", reference:"nss-tools-3.15.3-3.el6_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
