#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(80016);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/12/18 14:26:57 $");

  script_cve_id("CVE-2013-6435", "CVE-2014-8118");

  script_name(english:"Scientific Linux Security Update : rpm on SL7.x x86_64");
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
"It was found that RPM wrote file contents to the target installation
directory under a temporary name, and verified its cryptographic
signature only after the temporary file has been written completely.
Under certain conditions, the system interprets the unverified
temporary file contents and extracts commands from it. This could
allow an attacker to modify signed RPM files in such a way that they
would execute code chosen by the attacker during package installation.
(CVE-2013-6435)

It was found that RPM could encounter an integer overflow, leading to
a stack-based buffer overflow, while parsing a crafted CPIO header in
the payload section of an RPM file. This could allow an attacker to
modify signed RPM files in such a way that they would execute code
chosen by the attacker during package installation. (CVE-2014-8118)

All running applications linked against the RPM library must be
restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=1453
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd4c4999"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rpm-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"rpm-apidocs-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rpm-build-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rpm-build-libs-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"SL7", reference:"rpm-cron-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rpm-debuginfo-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rpm-devel-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rpm-libs-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rpm-python-4.11.1-18.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"rpm-sign-4.11.1-18.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");