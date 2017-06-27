#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61202);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-3597");

  script_name(english:"Scientific Linux Security Update : perl on SL4.x, SL5.x i386/x86_64");
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
"Perl is a high-level programming language commonly used for system
administration utilities and web programming.

It was found that the 'new' constructor of the Digest module used its
argument as part of the string expression passed to the eval()
function. An attacker could possibly use this flaw to execute
arbitrary Perl code with the privileges of a Perl program that uses
untrusted input as an argument to the constructor. (CVE-2011-3597)

It was found that the Perl CGI module used a hard-coded value for the
MIME boundary string in multipart/x-mixed-replace content. A remote
attacker could possibly use this flaw to conduct an HTTP response
splitting attack via a specially crafted HTTP request. (CVE-2010-2761)

A CRLF injection flaw was found in the way the Perl CGI module
processed a sequence of non-whitespace preceded by newline characters
in the header. A remote attacker could use this flaw to conduct an
HTTP response splitting attack via a specially crafted sequence of
characters provided to the CGI module. (CVE-2010-4410)

All Perl users should upgrade to these updated packages, which contain
backported patches to correct these issues. All running Perl programs
must be restarted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1112&L=scientific-linux-errata&T=0&P=2385
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f9212bd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected perl, perl-debuginfo and / or perl-suidperl
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/08");
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
if (rpm_check(release:"SL4", reference:"perl-5.8.5-57.el4")) flag++;
if (rpm_check(release:"SL4", reference:"perl-debuginfo-5.8.5-57.el4")) flag++;
if (rpm_check(release:"SL4", reference:"perl-suidperl-5.8.5-57.el4")) flag++;

if (rpm_check(release:"SL5", reference:"perl-5.8.8-32.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"perl-debuginfo-5.8.8-32.el5_7.6")) flag++;
if (rpm_check(release:"SL5", reference:"perl-suidperl-5.8.8-32.el5_7.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
