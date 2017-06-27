#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0016 and 
# CentOS Errata and Security Advisory 2015:0016 respectively.
#

include("compat.inc");

if (description)
{
  script_id(80400);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/02/28 05:39:56 $");

  script_cve_id("CVE-2014-6040", "CVE-2014-7817");
  script_bugtraq_id(69472, 71216);
  script_osvdb_id(110668, 110669, 110670, 110671, 110672, 110673, 110675, 115032);
  script_xref(name:"RHSA", value:"2015:0016");

  script_name(english:"CentOS 6 : glibc (CESA-2015:0016)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix two security issues and two bugs are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The glibc packages provide the standard C libraries (libc), POSIX
thread libraries (libpthread), standard math libraries (libm), and the
Name Server Caching Daemon (nscd) used by multiple programs on the
system. Without these libraries, the Linux system cannot function
correctly.

An out-of-bounds read flaw was found in the way glibc's iconv()
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

The CVE-2014-7817 issue was discovered by Tim Waugh of the Red Hat
Developer Experience Team.

This update also fixes the following bugs :

* Previously, when an address lookup using the getaddrinfo() function
for the AF_UNSPEC value was performed on a defective DNS server, the
server in some cases responded with a valid response for the A record,
but a referral response for the AAAA record, which resulted in a
lookup failure. A prior update was implemented for getaddrinfo() to
return the valid response, but it contained a typographical error, due
to which the lookup could under some circumstances still fail. This
error has been corrected and getaddrinfo() now returns a valid
response in the described circumstances. (BZ#1172023)

* An error in the dlopen() library function previously caused
recursive calls to dlopen() to terminate unexpectedly or to abort with
a library assertion. This error has been fixed and recursive calls to
dlopen() no longer crash or abort. (BZ#1173469)

All glibc users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-January/020863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e0b853f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected glibc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"glibc-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-common-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-devel-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-headers-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-static-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"glibc-utils-2.12-1.149.el6_6.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"nscd-2.12-1.149.el6_6.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
