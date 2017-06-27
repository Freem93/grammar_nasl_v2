#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(60624);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2008-1679", "CVE-2008-1887", "CVE-2008-2315", "CVE-2008-3142", "CVE-2008-3143", "CVE-2008-3144", "CVE-2008-4864", "CVE-2008-5031");

  script_name(english:"Scientific Linux Security Update : python for SL 3.0.x on i386/x86_64");
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
"When the assert() system call was disabled, an input sanitization flaw
was revealed in the Python string object implementation that led to a
buffer overflow. The missing check for negative size values meant the
Python memory allocator could allocate less memory than expected. This
could result in arbitrary code execution with the Python interpreter's
privileges. (CVE-2008-1887)

Multiple buffer and integer overflow flaws were found in the Python
Unicode string processing and in the Python Unicode and string object
implementations. An attacker could use these flaws to cause a denial
of service (Python application crash). (CVE-2008-3142, CVE-2008-5031)

Multiple integer overflow flaws were found in the Python imageop
module. If a Python application used the imageop module to process
untrusted images, it could cause the application to crash or,
potentially, execute arbitrary code with the Python interpreter's
privileges. (CVE-2008-1679, CVE-2008-4864)

Multiple integer underflow and overflow flaws were found in the Python
snprintf() wrapper implementation. An attacker could use these flaws
to cause a denial of service (memory corruption). (CVE-2008-3144)

Multiple integer overflow flaws were found in various Python modules.
An attacker could use these flaws to cause a denial of service (Python
application crash). (CVE-2008-2315, CVE-2008-3143)

Would like to thank David Remahl of the Apple Product Security team
for responsibly reporting the CVE-2008-1679 and CVE-2008-2315 issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0907&L=scientific-linux-errata&T=0&P=2408
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82527a2d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

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
if (rpm_check(release:"SL3", reference:"python-2.2.3-6.11")) flag++;
if (rpm_check(release:"SL3", reference:"python-devel-2.2.3-6.11")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"python-docs-2.2.3-6.11")) flag++;
if (rpm_check(release:"SL3", reference:"python-tools-2.2.3-6.11")) flag++;
if (rpm_check(release:"SL3", reference:"tkinter-2.2.3-6.11")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
