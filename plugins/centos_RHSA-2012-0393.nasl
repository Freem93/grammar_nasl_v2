#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0393 and 
# CentOS Errata and Security Advisory 2012:0393 respectively.
#

include("compat.inc");

if (description)
{
  script_id(58390);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/28 18:05:37 $");

  script_cve_id("CVE-2012-0864");
  script_bugtraq_id(52201);
  script_osvdb_id(79705);
  script_xref(name:"RHSA", value:"2012:0393");

  script_name(english:"CentOS 6 : glibc (CESA-2012:0393)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix one security issue and three bugs are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The glibc packages provide the standard C and standard math libraries
used by multiple programs on the system. Without these libraries, the
Linux system cannot function correctly.

An integer overflow flaw was found in the implementation of the printf
functions family. This could allow an attacker to bypass
FORTIFY_SOURCE protections and execute arbitrary code using a format
string flaw in an application, even though these protections are
expected to limit the impact of such flaws to an application abort.
(CVE-2012-0864)

This update also fixes the following bugs :

* Previously, the dynamic loader generated an incorrect ordering for
initialization according to the ELF specification. This could result
in incorrect ordering of DSO constructors and destructors. With this
update, dependency resolution has been fixed. (BZ#783999)

* Previously, locking of the main malloc arena was incorrect in the
retry path. This could result in a deadlock if an sbrk request failed.
With this update, locking of the main arena in the retry path has been
fixed. This issue was exposed by a bug fix provided in the
RHSA-2012:0058 update. (BZ#795328)

* Calling memcpy with overlapping arguments on certain processors
would generate unexpected results. While such code is a clear
violation of ANSI/ISO standards, this update restores prior memcpy
behavior. (BZ#799259)

All users of glibc are advised to upgrade to these updated packages,
which contain patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-March/018503.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a53ed83"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"glibc-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-common-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-devel-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-headers-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-static-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-utils-2.12-1.47.el6_2.9")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nscd-2.12-1.47.el6_2.9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
