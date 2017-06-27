#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61203);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/27 14:30:01 $");

  script_cve_id("CVE-2011-4516");

  script_name(english:"Scientific Linux Security Update : jasper on SL6.x i386/x86_64");
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
"JasPer is an implementation of Part 1 of the JPEG 2000 image
compression standard.

Two heap-based buffer overflow flaws were found in the way JasPer
decoded JPEG 2000 compressed image files. An attacker could create a
malicious JPEG 2000 compressed image file that, when opened, would
cause applications that use JasPer (such as Nautilus) to crash or,
potentially, execute arbitrary code. (CVE-2011-4516, CVE-2011-4517)

Users are advised to upgrade to these updated packages, which contain
a backported patch to correct these issues. All applications using the
JasPer libraries (such as Nautilus) must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=3527
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6a65cd9b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"jasper-1.900.1-15.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-debuginfo-1.900.1-15.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-devel-1.900.1-15.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-libs-1.900.1-15.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"jasper-utils-1.900.1-15.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
