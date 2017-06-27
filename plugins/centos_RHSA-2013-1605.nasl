#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1605 and 
# CentOS Errata and Security Advisory 2013:1605 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79166);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4332");
  script_bugtraq_id(57638, 58839, 62324);
  script_osvdb_id(89747, 92038, 97246, 97247, 97248);
  script_xref(name:"RHSA", value:"2013:1605");

  script_name(english:"CentOS 6 : glibc (CESA-2013:1605)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix three security issues, several bugs,
and add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
Name Server Caching Daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

Multiple integer overflow flaws, leading to heap-based buffer
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

* Due to a defect in the initial release of the getaddrinfo() system
call in Red Hat enterprise Linux 6.0, AF_INET and AF_INET6 queries
resolved from the /etc/hosts file returned queried names as canonical
names. This incorrect behavior is, however, still considered to be the
expected behavior. As a result of a recent change in getaddrinfo(),
AF_INET6 queries started resolving the canonical names correctly.
However, this behavior was unexpected by applications that relied on
queries resolved from the /etc/hosts file, and these applications
could thus fail to operate properly. This update applies a fix
ensuring that AF_INET6 queries resolved from /etc/hosts always return
the queried name as canonical. Note that DNS lookups are resolved
properly and always return the correct canonical names. A proper fix
to AF_INET6 queries resolution from /etc/hosts may be applied in
future releases; for now, due to a lack of standard, Red Hat suggests
the first entry in the /etc/hosts file, that applies for the IP
address being resolved, to be considered the canonical entry.
(BZ#1022022)

These updated glibc packages also include additional bug fixes and
various enhancements. Space precludes documenting all of these changes
in this advisory. Users are directed to the Red Hat Enterprise Linux
6.5 Technical Notes, linked to in the References, for information on
the most significant of these changes.

All glibc users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add these
enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/000947.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67cbe4a1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"glibc-2.12-1.132.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-common-2.12-1.132.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-devel-2.12-1.132.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-headers-2.12-1.132.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-static-2.12-1.132.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-utils-2.12-1.132.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nscd-2.12-1.132.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
