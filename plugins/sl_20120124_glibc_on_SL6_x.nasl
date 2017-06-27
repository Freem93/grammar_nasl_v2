#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61223);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/05/04 23:38:20 $");

  script_cve_id("CVE-2009-5029", "CVE-2011-4609");

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
"The glibc packages contain the standard C libraries used by multiple
programs on the system. These packages contain the standard C and the
standard math libraries. Without these two libraries, a Linux system
cannot function properly.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way the glibc library read timezone files. If a
carefully-crafted timezone file was loaded by an application linked
against glibc, it could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2009-5029)

A denial of service flaw was found in the remote procedure call (RPC)
implementation in glibc. A remote attacker able to open a large number
of connections to an RPC service that is using the RPC implementation
from glibc, could use this flaw to make that service use an excessive
amount of CPU time. (CVE-2011-4609)

This update also fixes the following bugs :

  - glibc had incorrect information for numeric separators
    and groupings for specific French, Spanish, and German
    locales. Therefore, applications utilizing glibc's
    locale support printed numbers with the wrong separators
    and groupings when those locales were in use. With this
    update, the separator and grouping information has been
    fixed.

  - The 2.12-1.25.el6_1.3 glibc update introduced a
    regression, causing glibc to incorrectly parse groups
    with more than 126 members, resulting in applications
    such as 'id' failing to list all the groups a particular
    user was a member of. With this update, group parsing
    has been fixed.

  - glibc incorrectly allocated too much memory due to a
    race condition within its own malloc routines. This
    could cause a multi-threaded application to allocate
    more memory than was expected. With this update, the
    race condition has been fixed, and malloc's behavior is
    now consistent with the documentation regarding the
    MALLOC_ARENA_TEST and MALLOC_ARENA_MAX environment
    variables.

Users should upgrade to these updated packages, which contain
backported patches to resolve these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1201&L=scientific-linux-errata&T=0&P=1716
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?42c155a6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"glibc-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-common-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-debuginfo-common-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-devel-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-headers-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-static-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"glibc-utils-2.12-1.47.el6_2.5")) flag++;
if (rpm_check(release:"SL6", reference:"nscd-2.12-1.47.el6_2.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
