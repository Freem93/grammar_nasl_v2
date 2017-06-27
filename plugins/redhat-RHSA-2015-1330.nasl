#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1330. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84938);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2013-1752", "CVE-2014-1912", "CVE-2014-4650", "CVE-2014-7185");
  script_bugtraq_id(63804, 65379, 68147, 70089);
  script_osvdb_id(101381, 101382, 101383, 101384, 101385, 101386, 102929, 108369, 112028);
  script_xref(name:"RHSA", value:"2015:1330");

  script_name(english:"RHEL 6 : python (RHSA-2015:1330)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
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
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-1912.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-4650.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-7185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/1495363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1330.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1330";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-debuginfo-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-devel-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"python-libs-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-test-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-test-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-test-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"python-tools-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"python-tools-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"python-tools-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"tkinter-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"tkinter-2.6.6-64.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"tkinter-2.6.6-64.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debuginfo / python-devel / python-libs / etc");
  }
}
