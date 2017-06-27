#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(71193);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:29 $");

  script_cve_id("CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4332");

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
"Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in glibc's memory allocator functions (pvalloc,
valloc, and memalign). If an application used such a function, it
could cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2013-4332)

A flaw was found in the regular expression matching routines that
process multibyte character input. If an application utilized the
glibc regular expression matching mechanism, an attacker could provide
specially crafted input that, when processed, would cause the
application to crash. (CVE-2013-0242)

It was found that getaddrinfo() did not limit the amount of stack
memory used during name resolution. An attacker able to make an
application resolve an attacker-controlled hostname or IP address
could possibly cause the application to exhaust all stack memory and
crash. (CVE-2013-1914)

Among other changes, this update includes an important fix for the
following bug :

  - Due to a defect in the initial release of the
    getaddrinfo() system call in Scientific Linux 6.0,
    AF_INET and AF_INET6 queries resolved from the
    /etc/hosts file returned queried names as canonical
    names. This incorrect behavior is, however, still
    considered to be the expected behavior. As a result of a
    recent change in getaddrinfo(), AF_INET6 queries started
    resolving the canonical names correctly. However, this
    behavior was unexpected by applications that relied on
    queries resolved from the /etc/hosts file, and these
    applications could thus fail to operate properly. This
    update applies a fix ensuring that AF_INET6 queries
    resolved from /etc/hosts always return the queried name
    as canonical. Note that DNS lookups are resolved
    properly and always return the correct canonical names.
    A proper fix to AF_INET6 queries resolution from
    /etc/hosts may be applied in future releases; for now,
    due to a lack of standard, Red Hat suggests the first
    entry in the /etc/hosts file, that applies for the IP
    address being resolved, to be considered the canonical
    entry."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1312&L=scientific-linux-errata&T=0&P=448
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?030c8ddc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"glibc-2.12-1.132.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.132.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-2.12-1.132.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-common-2.12-1.132.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.132.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.132.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.132.el6")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.132.el6")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.132.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
