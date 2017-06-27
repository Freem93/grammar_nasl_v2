#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:1294. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63998);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2011-3192");
  script_bugtraq_id(49303);
  script_xref(name:"RHSA", value:"2011:1294");

  script_name(english:"RHEL 5 / 6 : httpd (RHSA-2011:1294)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated httpd packages that fix one security issue are now available
for Red Hat Enterprise Linux 5.3 Long Life, 5.6 Extended Update
Support, and 6.0 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The Apache HTTP Server is a popular web server.

A flaw was found in the way the Apache HTTP Server handled Range HTTP
headers. A remote attacker could use this flaw to cause httpd to use
an excessive amount of memory and CPU time via HTTP requests with a
specially crafted Range header. (CVE-2011-3192)

All httpd users should upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing the
updated packages, the httpd daemon must be restarted for the update to
take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3192.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-1294.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"httpd-2.2.3-22.el5_3.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"httpd-2.2.3-22.el5_3.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"httpd-devel-2.2.3-22.el5_3.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"httpd-devel-2.2.3-22.el5_3.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"httpd-manual-2.2.3-22.el5_3.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"httpd-manual-2.2.3-22.el5_3.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"i386", reference:"mod_ssl-2.2.3-22.el5_3.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"3", cpu:"x86_64", reference:"mod_ssl-2.2.3-22.el5_3.3")) flag++;

if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"httpd-2.2.3-45.el5_6.2")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"httpd-2.2.3-45.el5_6.2")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"httpd-2.2.3-45.el5_6.2")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", reference:"httpd-devel-2.2.3-45.el5_6.2")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"httpd-manual-2.2.3-45.el5_6.2")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"httpd-manual-2.2.3-45.el5_6.2")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"httpd-manual-2.2.3-45.el5_6.2")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"i386", reference:"mod_ssl-2.2.3-45.el5_6.2")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"s390x", reference:"mod_ssl-2.2.3-45.el5_6.2")) flag++;
if (rpm_check(release:"RHEL5", sp:"6", cpu:"x86_64", reference:"mod_ssl-2.2.3-45.el5_6.2")) flag++;

if (rpm_check(release:"RHEL6", cpu:"i686", reference:"httpd-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"httpd-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"httpd-debuginfo-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"httpd-devel-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", reference:"httpd-manual-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"httpd-tools-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"httpd-tools-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"httpd-tools-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mod_ssl-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mod_ssl-2.2.15-5.el6_0.1")) flag++;
if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mod_ssl-2.2.15-5.el6_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
