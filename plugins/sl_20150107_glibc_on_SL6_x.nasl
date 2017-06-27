#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(80409);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/02/28 05:39:56 $");

  script_cve_id("CVE-2014-6040", "CVE-2014-7817");

  script_name(english:"Scientific Linux Security Update : glibc on SL6.x i386/x86_64");
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
"An out-of-bounds read flaw was found in the way glibc's iconv()
function converted certain encoded data to UTF-8. An attacker able to
make an application call the iconv() function with a specially crafted
argument could use this flaw to crash that application.
(CVE-2014-6040)

It was found that the wordexp() function would perform command
substitution even when the WRDE_NOCMD flag was specified. An attacker
able to provide specially crafted input to an application using the
wordexp() function, and not sanitizing the input correctly, could
potentially use this flaw to execute arbitrary commands with the
credentials of the user running that application. (CVE-2014-7817)

This update also fixes the following bugs :

  - Previously, when an address lookup using the
    getaddrinfo() function for the AF_UNSPEC value was
    performed on a defective DNS server, the server in some
    cases responded with a valid response for the A record,
    but a referral response for the AAAA record, which
    resulted in a lookup failure. A prior update was
    implemented for getaddrinfo() to return the valid
    response, but it contained a typographical error, due to
    which the lookup could under some circumstances still
    fail. This error has been corrected and getaddrinfo()
    now returns a valid response in the described
    circumstances.

  - An error in the dlopen() library function previously
    caused recursive calls to dlopen() to terminate
    unexpectedly or to abort with a library assertion. This
    error has been fixed and recursive calls to dlopen() no
    longer crash or abort."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1501&L=scientific-linux-errata&T=0&P=532
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a90c9644"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"glibc-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-common-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.149.el6_6.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
