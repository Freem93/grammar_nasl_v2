#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1411 and 
# CentOS Errata and Security Advisory 2013:1411 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79155);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:05:38 $");

  script_cve_id("CVE-2013-4332");
  script_bugtraq_id(62324);
  script_osvdb_id(97246, 97247, 97248);
  script_xref(name:"RHSA", value:"2013:1411");

  script_name(english:"CentOS 5 : glibc (CESA-2013:1411)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix one security issue and one bug are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

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

This update also fixes the following bug :

* Prior to this update, the size of the L3 cache in certain CPUs for
SMP (Symmetric Multiprocessing) servers was not correctly detected.
The incorrect cache size detection resulted in less than optimal
performance for routines that used this information, including the
memset() function. To fix this bug, the cache size detection has been
corrected and core routines including memset() have their performance
restored to expected levels. (BZ#1011424)

All glibc users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-October/000888.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?371f513d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
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
if (rpm_check(release:"CentOS-5", reference:"glibc-2.5-118.el5_10.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-common-2.5-118.el5_10.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-devel-2.5-118.el5_10.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-headers-2.5-118.el5_10.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"glibc-utils-2.5-118.el5_10.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nscd-2.5-118.el5_10.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
