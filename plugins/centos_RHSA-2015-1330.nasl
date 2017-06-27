#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1330 and 
# CentOS Errata and Security Advisory 2015:1330 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85012);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/07/28 18:22:13 $");

  script_cve_id("CVE-2013-1752", "CVE-2014-1912", "CVE-2014-4650", "CVE-2014-7185");
  script_bugtraq_id(63804, 65379, 68147, 70089);
  script_osvdb_id(101381, 101382, 101383, 101384, 101385, 101386, 102929, 108369, 112028);
  script_xref(name:"RHSA", value:"2015:1330");

  script_name(english:"CentOS 6 : python (CESA-2015:1330)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated python packages that fix multiple security issues, several
bugs and add one enhancement are now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Python is an interpreted, interactive, object-oriented programming
language often compared to Tcl, Perl, Scheme, or Java. Python includes
modules, classes, exceptions, very high level dynamic data types and
dynamic typing. Python supports interfaces to many system calls and
libraries, as well as to various windowing systems (X11, Motif, Tk,
Mac and MFC).

It was discovered that the socket.recvfrom_into() function failed to
check the size of the supplied buffer. This could lead to a buffer
overflow when the function was called with an insufficiently sized
buffer. (CVE-2014-1912)

It was discovered that multiple Python standard library modules
implementing network protocols (such as httplib or smtplib) failed to
restrict the sizes of server responses. A malicious server could cause
a client using one of the affected modules to consume an excessive
amount of memory. (CVE-2013-1752)

It was discovered that the CGIHTTPServer module incorrectly handled
URL encoded paths. A remote attacker could use this flaw to execute
scripts outside of the cgi-bin directory, or disclose the source code
of the scripts in the cgi-bin directory. (CVE-2014-4650)

An integer overflow flaw was found in the way the buffer() function
handled its offset and size arguments. An attacker able to control
these arguments could use this flaw to disclose portions of the
application memory or cause it to crash. (CVE-2014-7185)

These updated python packages also include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. For information on the most significant of these changes,
users are directed to the following article on the Red Hat Customer
Portal :

https://access.redhat.com/articles/1495363

All python users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues and add this
enhancement."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/001906.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?215fca08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

# Temp disable
exit(0, 'Temporarily disabled.');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"python-2.6.6-64.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-devel-2.6.6-64.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-libs-2.6.6-64.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-test-2.6.6-64.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-tools-2.6.6-64.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tkinter-2.6.6-64.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
