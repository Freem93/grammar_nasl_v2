#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:256 and 
# CentOS Errata and Security Advisory 2005:256 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21800);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/08/24 13:49:05 $");

  script_cve_id("CVE-2004-1453");
  script_osvdb_id(9010);
  script_xref(name:"RHSA", value:"2005:256");

  script_name(english:"CentOS 3 : glibc (CESA-2005:256)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that address several bugs are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The GNU libc packages (known as glibc) contain the standard C
libraries used by applications.

It was discovered that the use of LD_DEBUG, LD_SHOW_AUXV, and
LD_DYNAMIC_WEAK were not restricted for a setuid program. A local user
could utilize this flaw to gain information, such as the list of
symbols used by the program. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-1453 to this
issue.

This erratum addresses the following bugs in the GNU C Library :

  - fix stack alignment in IA-32 clone - fix double free in
    globfree - fix fnmatch to avoid jumping based on
    uninitialized memory read - fix fseekpos after ungetc -
    fix TZ env var handling if the variable ends with + or -
    - avoid depending on values read from uninitialized
    memory in strtold on certain architectures - fix mapping
    alignment computation in dl-load - fix i486+ strncat
    inline assembly - make gethostid/sethostid work on
    bi-arch platforms - fix ppc64 getcontext/swapcontext -
    fix pthread_exit if called after pthread_create, but
    before the created thread actually started - fix return
    values for tgamma (+-0) - fix handling of very long
    lines in /etc/hosts - avoid page aliasing of thread
    stacks on AMD64 - avoid busy loop in malloc if
    concurrent with fork - allow putenv and setenv in shared
    library constructors - fix restoring of CCR in
    swapcontext and getcontext on ppc64 - avoid using
    sigaction (SIGPIPE, ...) in syslog implementation

All users of glibc should upgrade to these updated packages, which
resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011675.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011720.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011721.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011729.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2005-May/011730.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nptl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"glibc-2.3.2-95.33")) flag++;
if (rpm_check(release:"CentOS-3", reference:"glibc-common-2.3.2-95.33")) flag++;
if (rpm_check(release:"CentOS-3", reference:"glibc-debug-2.3.2-95.33")) flag++;
if (rpm_check(release:"CentOS-3", reference:"glibc-devel-2.3.2-95.33")) flag++;
if (rpm_check(release:"CentOS-3", reference:"glibc-headers-2.3.2-95.33")) flag++;
if (rpm_check(release:"CentOS-3", reference:"glibc-profile-2.3.2-95.33")) flag++;
if (rpm_check(release:"CentOS-3", reference:"glibc-utils-2.3.2-95.33")) flag++;
if (rpm_check(release:"CentOS-3", reference:"nptl-devel-2.3.2-95.33")) flag++;
if (rpm_check(release:"CentOS-3", reference:"nscd-2.3.2-95.33")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
