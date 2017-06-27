#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60319);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2007-6110");

  script_name(english:"Scientific Linux Security Update : htdig on SL5.x, SL4.x i386/x86_64");
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
"A cross-site scripting flaw was discovered in a htdig search page. An
attacker could construct a carefully crafted URL, which once visited
by an unsuspecting user, could cause a user's Web browser to execute
malicious script in the context of the visited htdig search Web page.
(CVE-2007-6110)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0712&L=scientific-linux-errata&T=0&P=544
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f8e9abc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected htdig and / or htdig-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/03");
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
if (rpm_check(release:"SL4", cpu:"i386", reference:"htdig-3.2.0b6-4.el4_6")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"htdig-3.2.0b6-4.el4")) flag++;
if (rpm_check(release:"SL4", cpu:"i386", reference:"htdig-web-3.2.0b6-4.el4_6")) flag++;
if (rpm_check(release:"SL4", cpu:"x86_64", reference:"htdig-web-3.2.0b6-4.el4")) flag++;

if (rpm_check(release:"SL5", reference:"htdig-3.2.0b6-9.0.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"htdig-web-3.2.0b6-9.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
