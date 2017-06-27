#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0848. The text
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66537);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/09/09 19:10:17 $");

  script_cve_id("CVE-2013-2056");
  script_bugtraq_id(60075);
  script_osvdb_id(93566);
  script_xref(name:"RHSA", value:"2013:0848");

  script_name(english:"RHEL 5 / 6 : spacewalk-backend in Satellite Server (RHSA-2013:0848)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Updated spacewalk-backend packages that fix one security issue are now
available for Red Hat Network Satellite 5.3, 5.4, and 5.5.

The Red Hat Security Response Team has rated this update as having a
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Network (RHN) Satellite is a system management tool for
Linux-based infrastructures. It allows for provisioning, monitoring,
and remote management of multiple Linux deployments with a single,
centralized tool.

It was discovered that Red Hat Network Satellite did not fully check
the authenticity of a client beyond the initial authentication check
during an Inter-Satellite Sync operation. If a remote attacker were to
modify the satellite-sync client to skip the initial authentication
call, they could obtain all channel content from any Red Hat Network
Satellite server that could be reached, even if Inter-Satellite Sync
support was disabled. (CVE-2013-2056)

This issue was discovered by Jan Pazdziora of the Red Hat Satellite
Engineering team.

Users of Red Hat Network Satellite 5.3, 5.4, and 5.5 are advised to
upgrade to these updated packages, which resolve this issue. For this
update to take effect, Red Hat Network Satellite must be restarted.
Refer to the Solution section for details.");
  script_set_attribute(attribute:"see_also", value:"http://rhn.redhat.com/errata/RHSA-2013-0848.html");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2013:0848.html");
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/cve/CVE-2013-2056.html");
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-app");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-applet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-config-files-tool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-iss-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-package-push-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-sql-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-upload-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xml-export-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-backend-xp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/22");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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

if (! (rpm_exists(release:"RHEL5", rpm:"spacewalk-backend-app-") || rpm_exists(release:"RHEL6", rpm:"spacewalk-backend-app-"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "Satellite Server");

# Red Hat Network Satellite (v. 5.4 for RHEL 5/6), spacewalk-backend-1.2
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-app-1.7.0-0.el5sat") || rpm_check(release:"RHEL6", reference:"spacewalk-backend-app-1.7.0-0.el6sat"))
{
  # Clear existing test list and report
  __pkg_tests = make_list();
  __rpm_report = '';
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-app-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-applet-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-common-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-tool-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-iss-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-iss-export-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-libs-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-package-push-server-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-server-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-sql-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-sql-oracle-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-tools-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-upload-server-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xml-export-libs-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xmlrpc-1.2.13-79.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xp-1.2.13-79.el5sat")) flag++;

  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-app-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-applet-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-common-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-tool-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-iss-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-iss-export-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-libs-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-package-push-server-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-server-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-oracle-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-tools-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-upload-server-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-xml-export-libs-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-xmlrpc-1.2.13-79.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-xp-1.2.13-79.el6sat")) flag++;
}

# Red Hat Network Satellite (v. 5.5 for RHEL 5/6), spacewalk-backend-1.7
else
{
  # Clear existing test list and report
  __pkg_tests = make_list();
  __rpm_report = '';
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-app-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-applet-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-common-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-tool-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-iss-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-iss-export-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-libs-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-package-push-server-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-server-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-sql-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-sql-oracle-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-tools-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xml-export-libs-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xmlrpc-1.7.38-45.el5sat")) flag++;
  if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xp-1.7.38-45.el5sat")) flag++;

  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-app-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-applet-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-common-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-config-files-tool-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-iss-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-iss-export-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-libs-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-package-push-server-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-server-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-sql-oracle-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-tools-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-xml-export-libs-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-xmlrpc-1.7.38-45.el6sat")) flag++;
  if (rpm_check(release:"RHEL6", reference:"spacewalk-backend-xp-1.7.38-45.el6sat")) flag++;
}

# Red Hat Network Satellite (v. 5.3 for RHEL 5), spacewalk-backend-0.5
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-app-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-applet-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-common-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-tool-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-iss-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-iss-export-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-package-push-server-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-server-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-sql-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-tools-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-upload-server-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xml-export-libs-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xmlrpc-0.5.28-59.3.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xp-0.5.28-59.3.el5sat")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "Satellite Server");
