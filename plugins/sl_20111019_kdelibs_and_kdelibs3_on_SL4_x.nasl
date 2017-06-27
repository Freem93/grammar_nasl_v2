#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61159);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-3365");

  script_name(english:"Scientific Linux Security Update : kdelibs and kdelibs3 on SL4.x, SL5.x, SL6.x i386/x86_64");
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
"The kdelibs and kdelibs3 packages provide libraries for the K Desktop
Environment (KDE).

An input sanitization flaw was found in the KSSL (KDE SSL Wrapper)
API. An attacker could supply a specially crafted SSL certificate (for
example, via a web page) to an application using KSSL, such as the
Konqueror web browser, causing misleading information to be presented
to the user, possibly tricking them into accepting the certificate as
valid. (CVE-2011-3365)

Users should upgrade to these updated packages, which contain a
backported patch to correct this issue. The desktop must be restarted
(log out, then log back in) for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1110&L=scientific-linux-errata&T=0&P=1997
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b2242d0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"kdelibs-3.3.1-18.el4")) flag++;
if (rpm_check(release:"SL4", reference:"kdelibs-debuginfo-3.3.1-18.el4")) flag++;
if (rpm_check(release:"SL4", reference:"kdelibs-devel-3.3.1-18.el4")) flag++;

if (rpm_check(release:"SL5", reference:"kdelibs-3.5.4-26.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"kdelibs-apidocs-3.5.4-26.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"kdelibs-debuginfo-3.5.4-26.el5_7.1")) flag++;
if (rpm_check(release:"SL5", reference:"kdelibs-devel-3.5.4-26.el5_7.1")) flag++;

if (rpm_check(release:"SL6", reference:"kdelibs3-3.5.10-24.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"kdelibs3-apidocs-3.5.10-24.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"kdelibs3-debuginfo-3.5.10-24.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"kdelibs3-devel-3.5.10-24.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
