#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60568);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0163", "CVE-2009-0166", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");

  script_name(english:"Scientific Linux Security Update : cups on SL4.x, SL5.x i386/x86_64");
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
"Multiple integer overflow flaws were found in the CUPS JBIG2 decoder.
An attacker could create a malicious PDF file that would cause CUPS to
crash or, potentially, execute arbitrary code as the 'lp' user if the
file was printed. (CVE-2009-0147, CVE-2009-1179)

Multiple buffer overflow flaws were found in the CUPS JBIG2 decoder.
An attacker could create a malicious PDF file that would cause CUPS to
crash or, potentially, execute arbitrary code as the 'lp' user if the
file was printed. (CVE-2009-0146, CVE-2009-1182)

Multiple flaws were found in the CUPS JBIG2 decoder that could lead to
the freeing of arbitrary memory. An attacker could create a malicious
PDF file that would cause CUPS to crash or, potentially, execute
arbitrary code as the 'lp' user if the file was printed.
(CVE-2009-0166, CVE-2009-1180)

Multiple input validation flaws were found in the CUPS JBIG2 decoder.
An attacker could create a malicious PDF file that would cause CUPS to
crash or, potentially, execute arbitrary code as the 'lp' user if the
file was printed. (CVE-2009-0800)

An integer overflow flaw, leading to a heap-based buffer overflow, was
discovered in the Tagged Image File Format (TIFF) decoding routines
used by the CUPS image-converting filters, 'imagetops' and
'imagetoraster'. An attacker could create a malicious TIFF file that
could, potentially, execute arbitrary code as the 'lp' user if the
file was printed. (CVE-2009-0163)

Multiple denial of service flaws were found in the CUPS JBIG2 decoder.
An attacker could create a malicious PDF file that would cause CUPS to
crash when printed. (CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

After installing the update, the cupsd daemon will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0904&L=scientific-linux-errata&T=0&P=2085
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c7011d0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/16");
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
if (rpm_check(release:"SL4", reference:"cups-1.1.22-0.rc1.9.27.el4_7.5")) flag++;
if (rpm_check(release:"SL4", reference:"cups-devel-1.1.22-0.rc1.9.27.el4_7.5")) flag++;
if (rpm_check(release:"SL4", reference:"cups-libs-1.1.22-0.rc1.9.27.el4_7.5")) flag++;

if (rpm_check(release:"SL5", reference:"cups-1.3.7-8.el5_3.4")) flag++;
if (rpm_check(release:"SL5", reference:"cups-devel-1.3.7-8.el5_3.4")) flag++;
if (rpm_check(release:"SL5", reference:"cups-libs-1.3.7-8.el5_3.4")) flag++;
if (rpm_check(release:"SL5", reference:"cups-lpd-1.3.7-8.el5_3.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
