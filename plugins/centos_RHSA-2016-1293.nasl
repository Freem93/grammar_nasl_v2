#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1293 and 
# CentOS Errata and Security Advisory 2016:1293 respectively.
#

include("compat.inc");

if (description)
{
  script_id(91787);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/04/18 13:37:17 $");

  script_cve_id("CVE-2016-4444", "CVE-2016-4446", "CVE-2016-4989");
  script_osvdb_id(140303, 140304, 140305, 140307);
  script_xref(name:"RHSA", value:"2016:1293");

  script_name(english:"CentOS 7 : setroubleshoot / setroubleshoot-plugins (CESA-2016:1293)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for setroubleshoot and setroubleshoot-plugins is now
available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The setroubleshoot packages provide tools to help diagnose SELinux
problems. When Access Vector Cache (AVC) messages are returned, an
alert can be generated that provides information about the problem and
helps to track its resolution.

The setroubleshoot-plugins package provides a set of analysis plugins
for use with setroubleshoot. Each plugin has the capacity to analyze
SELinux AVC data and system data to provide user friendly reports
describing how to interpret SELinux AVC denials.

Security Fix(es) :

* Shell command injection flaws were found in the way the
setroubleshoot executed external commands. A local attacker able to
trigger certain SELinux denials could use these flaws to execute
arbitrary code with privileges of the setroubleshoot user.
(CVE-2016-4989)

* Shell command injection flaws were found in the way the
setroubleshoot allow_execmod and allow_execstack plugins executed
external commands. A local attacker able to trigger an execmod or
execstack SELinux denial could use these flaws to execute arbitrary
code with privileges of the setroubleshoot user. (CVE-2016-4444,
CVE-2016-4446)

The CVE-2016-4444 and CVE-2016-4446 issues were discovered by Milos
Malik (Red Hat) and the CVE-2016-4989 issue was discovered by Red Hat
Product Security.

Note: On Red Hat Enterprise Linux 7.0 and 7.1, the setroubleshoot is
run with root privileges. Therefore, these issues could allow an
attacker to execute arbitrary code with root privileges."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-June/021939.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d43de5d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-June/021940.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fd34a895"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected setroubleshoot and / or setroubleshoot-plugins
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:setroubleshoot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:setroubleshoot-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:setroubleshoot-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"setroubleshoot-3.2.24-4.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"setroubleshoot-plugins-3.0.59-2.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"setroubleshoot-server-3.2.24-4.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
