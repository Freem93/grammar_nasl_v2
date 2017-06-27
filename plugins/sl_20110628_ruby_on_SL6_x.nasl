#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61077);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:56 $");

  script_cve_id("CVE-2011-0188", "CVE-2011-1004", "CVE-2011-1005");

  script_name(english:"Scientific Linux Security Update : ruby on SL6.x i386/x86_64");
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
"Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A flaw was found in the way large amounts of memory were allocated on
64-bit systems when using the BigDecimal class. A context-dependent
attacker could use this flaw to cause memory corruption, causing a
Ruby application that uses the BigDecimal class to crash or, possibly,
execute arbitrary code. This issue did not affect 32-bit systems.
(CVE-2011-0188)

A race condition flaw was found in the remove system entries method in
the FileUtils module. If a local user ran a Ruby script that uses this
method, a local attacker could use this flaw to delete arbitrary files
and directories accessible to that user via a symbolic link attack.
(CVE-2011-1004)

A flaw was found in the method for translating an exception message
into a string in the Exception class. A remote attacker could use this
flaw to bypass safe level 4 restrictions, allowing untrusted (tainted)
code to modify arbitrary, trusted (untainted) strings, which safe
level 4 restrictions would otherwise prevent. (CVE-2011-1005)

All Ruby users should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=5111
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfc4d929"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/28");
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
if (rpm_check(release:"SL6", reference:"ruby-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-devel-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-docs-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-irb-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-libs-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-rdoc-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-ri-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-static-1.8.7.299-7.el6_1.1")) flag++;
if (rpm_check(release:"SL6", reference:"ruby-tcltk-1.8.7.299-7.el6_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
