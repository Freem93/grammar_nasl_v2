#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1225. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61770);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2017/01/10 18:05:24 $");

  script_cve_id("CVE-2012-0547", "CVE-2012-1682", "CVE-2012-3136", "CVE-2012-4681");
  script_bugtraq_id(55213, 55336, 55337, 55339);
  script_osvdb_id(84867, 84980, 84981, 84982);
  script_xref(name:"RHSA", value:"2012:1225");

  script_name(english:"RHEL 6 : java-1.7.0-oracle (RHSA-2012:1225)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.7.0-oracle packages that fix several security issues
are now available for Red Hat Enterprise Linux 6 Supplementary.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The Oracle Java 7 release includes the Oracle Java 7 Runtime
Environment and the Oracle Java 7 Software Development Kit.

This update fixes several vulnerabilities in the Oracle Java 7 Runtime
Environment and the Oracle Java 7 Software Development Kit. Further
information about these flaws can be found on the Oracle Java SE
Security Alert page, listed in the References section. (CVE-2012-4681,
CVE-2012-1682, CVE-2012-3136, CVE-2012-0547)

Red Hat is aware that a public exploit for CVE-2012-4681 is available
that executes code without user interaction when a user visits a
malicious web page using a browser with the Oracle Java 7 web browser
plug-in enabled.

All users of java-1.7.0-oracle are advised to upgrade to these updated
packages, which provide Oracle Java 7 Update 7 and resolve these
issues. All running instances of Oracle Java must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0547.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-1682.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3136.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4681.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.oracle.com/technetwork/topics/security/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1225.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-1.7.0-oracle-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-1.7.0.7-1jpp.5.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-1.7.0.7-1jpp.5.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-devel-1.7.0.7-1jpp.5.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-devel-1.7.0.7-1jpp.5.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-jdbc-1.7.0.7-1jpp.5.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-jdbc-1.7.0.7-1jpp.5.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-plugin-1.7.0.7-1jpp.5.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-plugin-1.7.0.7-1jpp.5.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"java-1.7.0-oracle-src-1.7.0.7-1jpp.5.el6_3")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"java-1.7.0-oracle-src-1.7.0.7-1jpp.5.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
