#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1119 and 
# CentOS Errata and Security Advisory 2013:1119 respectively.
#

include("compat.inc");

if (description)
{
  script_id(69142);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/08/07 10:47:59 $");

  script_cve_id("CVE-2013-2219");
  script_bugtraq_id(61504);
  script_osvdb_id(95827);
  script_xref(name:"RHSA", value:"2013:1119");

  script_name(english:"CentOS 6 : 389-ds-base (CESA-2013:1119)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated 389-ds-base packages that fix one security issue and three
bugs are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The 389 Directory Server is an LDAPv3 compliant server. The base
packages include the Lightweight Directory Access Protocol (LDAP)
server and command-line utilities for server administration.

It was discovered that the 389 Directory Server did not honor defined
attribute access controls when evaluating search filter expressions. A
remote attacker (with permission to query the Directory Server) could
use this flaw to determine the values of restricted attributes via a
series of search queries with filter conditions that used restricted
attributes. (CVE-2013-2219)

This issue was discovered by Ludwig Krispenz of Red Hat.

This update also fixes the following bugs :

* Previously, the disk monitoring feature did not function properly.
If logging functionality was set to critical and logging was disabled,
rotated logs would be deleted. If the attribute
'nsslapd-errorlog-level' was explicitly set to any value, even zero,
the disk monitoring feature would not stop the Directory Server when
it was supposed to. This update corrects the disk monitoring feature
settings, and it no longer malfunctions in the described scenarios.
(BZ#972930)

* Previously, setting the 'nsslapd-disk-monitoring-threshold'
attribute via ldapmodify to a large value worked as expected; however,
a bug in ldapsearch caused such values for the option to be displayed
as negative values. This update corrects the bug in ldapsearch and
correct values are now displayed. (BZ#984970)

* If logging functionality was not set to critical, then the mount
point for the logs directory was incorrectly skipped during the disk
space check. (BZ#987850)

All 389-ds-base users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues.
After installing this update, the 389 server service will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-July/019883.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4100dd78"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected 389-ds-base packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-1.2.11.15-20.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-devel-1.2.11.15-20.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"389-ds-base-libs-1.2.11.15-20.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
