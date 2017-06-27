#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(82250);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/03/26 13:38:48 $");

  script_cve_id("CVE-2014-6040", "CVE-2014-8121");

  script_name(english:"Scientific Linux Security Update : glibc on SL7.x x86_64");
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

It was found that the files back end of Name Service Switch (NSS) did
not isolate iteration over an entire database from key-based look-up
API calls. An application performing look-ups on a database while
iterating over it could enter an infinite loop, leading to a denial of
service. (CVE-2014-8121)

This update also fixes the following bugs :

  - Due to problems with buffer extension and reallocation,
    the nscd daemon terminated unexpectedly with a
    segmentation fault when processing long netgroup
    entries. With this update, the handling of long netgroup
    entries has been corrected and nscd no longer crashes in
    the described scenario.

  - If a file opened in append mode was truncated with the
    ftruncate() function, a subsequent ftell() call could
    incorrectly modify the file offset. This update ensures
    that ftell() modifies the stream state only when it is
    in append mode and the buffer for the stream is not
    empty.

  - A defect in the C library headers caused builds with
    older compilers to generate incorrect code for the
    btowc() function in the older compatibility C++ standard
    library. Applications calling btowc() in the
    compatibility C++ standard library became unresponsive.
    With this update, the C library headers have been
    corrected, and the compatibility C++ standard library
    shipped with Scientific Linux has been rebuilt.
    Applications that rely on the compatibility C++ standard
    library no longer hang when calling btowc().

  - Previously, when using netgroups and the nscd daemon was
    set up to cache netgroup information, the sudo utility
    denied access to valid users. The bug in nscd has been
    fixed, and sudo now works in netgroups as expected."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=2889
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef60f244"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-2.17-78.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-common-2.17-78.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-debuginfo-2.17-78.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-debuginfo-common-2.17-78.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-devel-2.17-78.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-headers-2.17-78.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-static-2.17-78.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"glibc-utils-2.17-78.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"nscd-2.17-78.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
