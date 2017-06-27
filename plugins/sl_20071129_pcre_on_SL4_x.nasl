#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65042);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2006-7225", "CVE-2006-7226", "CVE-2006-7228", "CVE-2006-7230", "CVE-2007-1659", "CVE-2007-1660");

  script_name(english:"Scientific Linux Security Update : pcre on SL4.x, SL3.x i386/x86_64");
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
"Flaws were discovered in the way PCRE handles certain malformed
regular expressions. If an application linked against PCRE, such as
Konqueror, parsed a malicious regular expression, it may have been
possible to run arbitrary code as the user running the application.
(CVE-2006-7225, CVE-2006-7226, CVE-2006-7228, CVE-2006-7230,
CVE-2007-1660)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0712&L=scientific-linux-errata&T=0&P=79
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37f0bcb4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pcre and / or pcre-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"pcre-3.9-10.4")) flag++;
if (rpm_check(release:"SL3", reference:"pcre-devel-3.9-10.4")) flag++;

if (rpm_check(release:"SL4", cpu:"i386", reference:"pcre-4.5-4.el4_6.6")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"pcre-4.5-4.el4.6")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"pcre-devel-4.5-4.el4_6.6")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"pcre-devel-4.5-4.el4.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
