#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0879. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63982);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/08/18 18:39:01 $");

  script_cve_id("CVE-2009-4139");
  script_osvdb_id(73112);
  script_xref(name:"RHSA", value:"2011:0879");

  script_name(english:"RHEL 5 : spacewalk-java (RHSA-2011:0879)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated spacewalk-java packages that fix one security issue are now
available for Red Hat Network Satellite 5.4.1 for Red Hat Enterprise
Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Red Hat Network (RHN) Satellite provides a solution to organizations
requiring absolute control over and privacy of the maintenance and
package deployment of their servers. It allows organizations to
utilize the benefits of the Red Hat Network without having to provide
public Internet access to their servers or other client systems.

It was found that RHN Satellite did not protect against Cross-Site
Request Forgery (CSRF) attacks. If an authenticated RHN Satellite user
visited a specially crafted web page, it could lead to unauthorized
command execution with the privileges of that user, for example,
creating a new user account, granting administrator privileges to user
accounts, disabling the account of the current user, and so on.
(CVE-2009-4139)

Red Hat would like to thank Christian Johansson of Bitsec AB and
Thomas Biege of the SUSE Security Team for independently reporting
this issue.

Users of Red Hat Network Satellite 5.4.1 are advised to upgrade to
these updated spacewalk-java packages, which resolve this issue. For
this update to take effect, Red Hat Network Satellite must be
restarted. Refer to the Solution section for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-4139.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0879.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-java-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spacewalk-taskomatic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/16");
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
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-1.2.39-85.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-config-1.2.39-85.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-lib-1.2.39-85.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-java-oracle-1.2.39-85.el5sat")) flag++;
if (rpm_check(release:"RHEL5", reference:"spacewalk-taskomatic-1.2.39-85.el5sat")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
