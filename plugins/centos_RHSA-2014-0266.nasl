#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0266 and 
# CentOS Errata and Security Advisory 2014:0266 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72910);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/08/17 13:58:12 $");

  script_cve_id("CVE-2014-0106");
  script_bugtraq_id(65997);
  script_osvdb_id(104086);
  script_xref(name:"RHSA", value:"2014:0266");

  script_name(english:"CentOS 5 : sudo (CESA-2014:0266)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sudo package that fixes one security issue is now available
for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
Moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The sudo (superuser do) utility allows system administrators to give
certain users the ability to run commands as root.

A flaw was found in the way sudo handled its blacklist of environment
variables. When the 'env_reset' option was disabled, a user permitted
to run certain commands via sudo could use this flaw to run such a
command with one of the blacklisted environment variables set,
allowing them to run an arbitrary command with the target user's
privileges. (CVE-2014-0106)

Note: This issue does not affect the default configuration of the sudo
package as shipped with Red Hat Enterprise Linux 5.

Red Hat would like to thank Todd C. Miller for reporting this issue.
Upstream acknowledges Sebastien Macke as the original reporter.

All sudo users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-March/020194.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f43bc32"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sudo package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sudo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"sudo-1.7.2p1-29.el5_10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
