#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1223 and 
# CentOS Errata and Security Advisory 2012:1223 respectively.
#

include("compat.inc");

if (description)
{
  script_id(61789);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/20 13:54:05 $");

  script_cve_id("CVE-2012-0547", "CVE-2012-1682", "CVE-2012-3136", "CVE-2012-4681");
  script_bugtraq_id(55213, 55337);
  script_osvdb_id(84867, 84980, 84981, 84982);
  script_xref(name:"RHSA", value:"2012:1223");

  script_name(english:"CentOS 6 : java-1.7.0-openjdk (CESA-2012:1223)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-openjdk packages that fix several security issues
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the OpenJDK 7 Java Runtime Environment and the
OpenJDK 7 Software Development Kit.

Multiple improper permission check issues were discovered in the Beans
component in OpenJDK. An untrusted Java application or applet could
use these flaws to bypass Java sandbox restrictions. (CVE-2012-4681,
CVE-2012-1682, CVE-2012-3136)

A hardening fix was applied to the AWT component in OpenJDK, removing
functionality from the restricted SunToolkit class that was used in
combination with other flaws to bypass Java sandbox restrictions.
(CVE-2012-0547)

All users of java-1.7.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-September/018842.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38d36ff9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.7.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java 7 Applet Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");
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
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-1.7.0.5-2.2.1.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-demo-1.7.0.5-2.2.1.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-devel-1.7.0.5-2.2.1.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.5-2.2.1.el6_3.3")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.7.0-openjdk-src-1.7.0.5-2.2.1.el6_3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
