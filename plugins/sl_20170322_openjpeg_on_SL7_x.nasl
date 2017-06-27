#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(97935);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/24 14:02:38 $");

  script_cve_id("CVE-2016-5139", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-7163", "CVE-2016-9573", "CVE-2016-9675");

  script_name(english:"Scientific Linux Security Update : openjpeg on SL7.x x86_64");
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
"Security Fix(es) :

  - Multiple integer overflow flaws, leading to heap-based
    buffer overflows, were found in OpenJPEG. A specially
    crafted JPEG2000 image could cause an application using
    OpenJPEG to crash or, potentially, execute arbitrary
    code. (CVE-2016-5139, CVE-2016-5158, CVE-2016-5159,
    CVE-2016-7163)

  - An out-of-bounds read vulnerability was found in
    OpenJPEG, in the j2k_to_image tool. Converting a
    specially crafted JPEG2000 file to another format could
    cause the application to crash or, potentially, disclose
    some data from the heap. (CVE-2016-9573)

  - A heap-based buffer overflow vulnerability was found in
    OpenJPEG. A specially crafted JPEG2000 image, when read
    by an application using OpenJPEG, could cause the
    application to crash or, potentially, execute arbitrary
    code. (CVE-2016-9675)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1703&L=scientific-linux-errata&F=&S=&P=9984
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8c8bbb17"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openjpeg-1.5.1-16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openjpeg-debuginfo-1.5.1-16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openjpeg-devel-1.5.1-16.el7_3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"openjpeg-libs-1.5.1-16.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
