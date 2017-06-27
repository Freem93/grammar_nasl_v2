#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61217);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/26 05:42:54 $");

  script_cve_id("CVE-2010-4008", "CVE-2011-0216", "CVE-2011-1944", "CVE-2011-2834", "CVE-2011-3905", "CVE-2011-3919");

  script_name(english:"Scientific Linux Security Update : libxml2 on SL5.x i386/x86_64");
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
"The libxml2 library is a development toolbox providing the
implementation of various XML standards. One of those standards is the
XML Path Language (XPath), which is a language for addressing parts of
an XML document.

A heap-based buffer overflow flaw was found in the way libxml2 decoded
entity references with long names. A remote attacker could provide a
specially crafted XML file that, when opened in an application linked
against libxml2, would cause the application to crash or, potentially,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-3919)

An off-by-one error, leading to a heap-based buffer overflow, was
found in the way libxml2 parsed certain XML files. A remote attacker
could provide a specially crafted XML file that, when opened in an
application linked against libxml2, would cause the application to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2011-0216)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way libxml2 parsed certain XPath expressions. If an
attacker were able to supply a specially crafted XML file to an
application using libxml2, as well as an XPath expression for that
application to run against the crafted file, it could cause the
application to crash or, possibly, execute arbitrary code.
(CVE-2011-1944)

Flaws were found in the way libxml2 parsed certain XPath expressions.
If an attacker were able to supply a specially crafted XML file to an
application using libxml2, as well as an XPath expression for that
application to run against the crafted file, it could cause the
application to crash. (CVE-2010-4008, CVE-2011-2834)

An out-of-bounds memory read flaw was found in libxml2. A remote
attacker could provide a specially crafted XML file that, when opened
in an application linked against libxml2, would cause the application
to crash. (CVE-2011-3905)

Note: Scientific Linux does not ship any applications that use libxml2
in a way that would allow the CVE-2011-1944, CVE-2010-4008, and
CVE-2011-2834 flaws to be exploited; however, third-party applications
may allow XPath expressions to be passed which could trigger these
flaws.

All users of libxml2 are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1201&L=scientific-linux-errata&T=0&P=851
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a51b1fe"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"libxml2-2.6.26-2.1.12.el5_7.2")) flag++;
if (rpm_check(release:"SL5", reference:"libxml2-debuginfo-2.6.26-2.1.12.el5_7.2")) flag++;
if (rpm_check(release:"SL5", reference:"libxml2-devel-2.6.26-2.1.12.el5_7.2")) flag++;
if (rpm_check(release:"SL5", reference:"libxml2-python-2.6.26-2.1.12.el5_7.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
