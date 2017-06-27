#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61033);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:26 $");

  script_cve_id("CVE-2009-3720", "CVE-2010-1634", "CVE-2010-2089", "CVE-2010-3493", "CVE-2011-1015", "CVE-2011-1521");

  script_name(english:"Scientific Linux Security Update : python on SL4.x, SL5.x i386/x86_64");
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
"A flaw was found in the Python urllib and urllib2 libraries where they
would not differentiate between different target URLs when handling
automatic redirects. This caused Python applications using these
modules to follow any new URL that they understood, including the
'file://' URL type. This could allow a remote server to force a local
Python application to read a local file instead of the remote one,
possibly exposing local files that were not meant to be exposed.
(CVE-2011-1521)

Multiple flaws were found in the Python audioop module. Supplying
certain inputs could cause the audioop module to crash or, possibly,
execute arbitrary code. (CVE-2010-1634, CVE-2010-2089)

A race condition was found in the way the Python smtpd module handled
new connections. A remote user could use this flaw to cause a Python
script using the smtpd module to terminate. (CVE-2010-3493)

An information disclosure flaw was found in the way the Python
CGIHTTPServer module processed certain HTTP GET requests. A remote
attacker could use a specially crafted request to obtain the CGI
script's source code. (CVE-2011-1015)

A buffer over-read flaw was found in the way the Python Expat parser
handled malformed UTF-8 sequences when processing XML files. A
specially crafted XML file could cause Python applications using the
Python Expat parser to crash while parsing the file. (CVE-2009-3720)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1105&L=scientific-linux-errata&T=0&P=474
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b6e079c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/05");
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
if (rpm_check(release:"SL4", reference:"python-2.3.4-14.10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"python-devel-2.3.4-14.10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"python-docs-2.3.4-14.10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"python-tools-2.3.4-14.10.el4")) flag++;
if (rpm_check(release:"SL4", reference:"tkinter-2.3.4-14.10.el4")) flag++;

if (rpm_check(release:"SL5", reference:"python-2.4.3-44.el5")) flag++;
if (rpm_check(release:"SL5", reference:"python-devel-2.4.3-44.el5")) flag++;
if (rpm_check(release:"SL5", reference:"python-libs-2.4.3-44.el5")) flag++;
if (rpm_check(release:"SL5", reference:"python-tools-2.4.3-44.el5")) flag++;
if (rpm_check(release:"SL5", reference:"tkinter-2.4.3-44.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
