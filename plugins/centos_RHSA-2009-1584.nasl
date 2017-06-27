#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1584 and 
# CentOS Errata and Security Advisory 2009:1584 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67075);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-2409", "CVE-2009-3728", "CVE-2009-3869", "CVE-2009-3871", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3875", "CVE-2009-3876", "CVE-2009-3877", "CVE-2009-3879", "CVE-2009-3880", "CVE-2009-3881", "CVE-2009-3882", "CVE-2009-3883", "CVE-2009-3884", "CVE-2010-0079");
  script_bugtraq_id(36881);
  script_xref(name:"RHSA", value:"2009:1584");

  script_name(english:"CentOS 5 : java-1.6.0-openjdk (CESA-2009:1584)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.6.0-openjdk packages that fix several security issues
are now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

These packages provide the OpenJDK 6 Java Runtime Environment and the
OpenJDK 6 Software Development Kit. The Java Runtime Environment (JRE)
contains the software and tools that users need to run applications
written using the Java programming language.

An integer overflow flaw and buffer overflow flaws were found in the
way the JRE processed image files. An untrusted applet or application
could use these flaws to extend its privileges, allowing it to read
and write local files, as well as to execute local applications with
the privileges of the user running the applet or application.
(CVE-2009-3869, CVE-2009-3871, CVE-2009-3873, CVE-2009-3874)

An information leak was found in the JRE. An untrusted applet or
application could use this flaw to extend its privileges, allowing it
to read and write local files, as well as to execute local
applications with the privileges of the user running the applet or
application. (CVE-2009-3881)

It was discovered that the JRE still accepts certificates with MD2
hash signatures, even though MD2 is no longer considered a
cryptographically strong algorithm. This could make it easier for an
attacker to create a malicious certificate that would be treated as
trusted by the JRE. With this update, the JRE disables the use of the
MD2 algorithm inside signatures by default. (CVE-2009-2409)

A timing attack flaw was found in the way the JRE processed HMAC
digests. This flaw could aid an attacker using forged digital
signatures to bypass authentication checks. (CVE-2009-3875)

Two denial of service flaws were found in the JRE. These could be
exploited in server-side application scenarios that process
DER-encoded (Distinguished Encoding Rules) data. (CVE-2009-3876,
CVE-2009-3877)

An information leak was found in the way the JRE handled color
profiles. An attacker could use this flaw to discover the existence of
files outside of the color profiles directory. (CVE-2009-3728)

A flaw in the JRE with passing arrays to the X11GraphicsDevice API was
found. An untrusted applet or application could use this flaw to
access and modify the list of supported graphics configurations. This
flaw could also lead to sensitive information being leaked to
unprivileged code. (CVE-2009-3879)

It was discovered that the JRE passed entire objects to the logging
API. This could lead to sensitive information being leaked to either
untrusted or lower-privileged code from an attacker-controlled applet
which has access to the logging API and is therefore able to
manipulate (read and/or call) the passed objects. (CVE-2009-3880)

Potential information leaks were found in various mutable static
variables. These could be exploited in application scenarios that
execute untrusted scripting code. (CVE-2009-3882, CVE-2009-3883)

An information leak was found in the way the TimeZone.getTimeZone
method was handled. This method could load time zone files that are
outside of the [JRE_HOME]/lib/zi/ directory, allowing a remote
attacker to probe the local file system. (CVE-2009-3884)

Note: The flaws concerning applets in this advisory, CVE-2009-3869,
CVE-2009-3871, CVE-2009-3873, CVE-2009-3874, CVE-2009-3879,
CVE-2009-3880, CVE-2009-3881 and CVE-2009-3884, can only be triggered
in java-1.6.0-openjdk by calling the 'appletviewer' application.

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016328.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b379fdaa"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-November/016329.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f694420c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(22, 119, 189, 200, 264, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-1.6.0.0-1.7.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-demo-1.6.0.0-1.7.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-devel-1.6.0.0-1.7.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.0-1.7.b09.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"java-1.6.0-openjdk-src-1.6.0.0-1.7.b09.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
