#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0300. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63973);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/05/02 18:01:07 $");

  script_cve_id("CVE-2011-0717", "CVE-2011-0718");
  script_osvdb_id(72548, 72549);
  script_xref(name:"RHSA", value:"2011:0300");

  script_name(english:"RHEL 5 : Satellite Server (RHSA-2011:0300)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated packages that fix two security issues are now available for
Red Hat Network Satellite Server 5.4.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Red Hat Network Satellite Server (RHN Satellite Server) is a system
management tool for Linux-based infrastructures. It allows for the
provisioning, remote management and monitoring of multiple Linux
deployments with a single, centralized tool.

A session fixation flaw was found in the way RHN Satellite Server
handled session cookies. An RHN Satellite Server user able to pre-set
the session cookie in a victim's browser to a valid value could use
this flaw to hijack the victim's session after the next log in.
(CVE-2011-0717)

A flaw was found in the way RHN Satellite Server managed user
authentication. A time delay was not inserted after each failed log
in, which could allow a remote attacker to conduct a password guessing
attack efficiently. (CVE-2011-0718)

Red Hat would like to thank Thomas Biege of the SuSE Security Team for
reporting these issues.

Users of RHN Satellite Server 5.4 are advised to upgrade to these
updated packages, which contain backported patches to correct these
issues. RHN Satellite Server must be restarted ('rhn-satellite
restart') for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0717.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0718.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0300.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/24");
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
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-app-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-applet-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-common-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-config-files-tool-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-iss-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-iss-export-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-libs-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-package-push-server-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-server-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-sql-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-sql-oracle-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-tools-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-upload-server-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xml-export-libs-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xmlrpc-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-backend-xp-1.2.13-26.2.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-1.2.39-35.1.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-config-1.2.39-35.1.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-lib-1.2.39-35.1.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-oracle-1.2.39-35.1.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-taskomatic-1.2.39-35.1.el5sat")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
