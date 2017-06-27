#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0259. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63971);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/02 18:01:07 $");

  script_cve_id("CVE-2011-0558", "CVE-2011-0559", "CVE-2011-0560", "CVE-2011-0561", "CVE-2011-0571", "CVE-2011-0572", "CVE-2011-0573", "CVE-2011-0574", "CVE-2011-0575", "CVE-2011-0577", "CVE-2011-0578", "CVE-2011-0607", "CVE-2011-0608");
  script_osvdb_id(70911, 70913, 70914, 70915, 70916, 70917, 70918, 70919, 70920, 70921, 70922, 70923, 70976);
  script_xref(name:"RHSA", value:"2011:0259");

  script_name(english:"RHEL 4 : redhat-release (EOL Notice) (RHSA-2011:0259)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The flash-plugin package on Red Hat Enterprise Linux 4 contains
multiple security flaws and should no longer be used. This is the
1-month notification of Red Hat's plans to disable Adobe Flash Player
9 on Red Hat Enterprise Linux 4.

The Red Hat Security Response Team has rated this update as having
critical security impact.

The flash-plugin package contains a Mozilla Firefox compatible Adobe
Flash Player web browser plug-in.

Adobe Flash Player 9 is vulnerable to critical security flaws and
should no longer be used. A remote attacker could use these flaws to
execute arbitrary code with the privileges of the user running Flash
Player 9. (CVE-2011-0558, CVE-2011-0559, CVE-2011-0560, CVE-2011-0561,
CVE-2011-0571, CVE-2011-0572, CVE-2011-0573, CVE-2011-0574,
CVE-2011-0575, CVE-2011-0577, CVE-2011-0578, CVE-2011-0607,
CVE-2011-0608)

Adobe is no longer providing security updates for Adobe Flash Player
9, and is not providing a replacement Flash Player version compatible
with Red Hat Enterprise Linux 4.

In one month Red Hat plans to release an update for the flash-plugin
package that will prevent it from functioning. User wishing to
continue using Flash Player 9, despite the vulnerabilities, can add
the flash-plugin package to the up2date skip list. Refer to the
following Red Hat Knowledgebase article for instructions on adding a
package to the up2date skip list:
https://access.redhat.com/kb/docs/DOC-1639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kb2.adobe.com/cps/406/kb406791.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/kb/docs/DOC-1639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0259.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-plugin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:flash-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4.8");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/15");
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
if (rpm_check(release:"RHEL4", cpu:"i386", reference:"flash-plugin-9.0.289.0-2.el4")) flag++;

if (rpm_check(release:"RHEL4", sp:"8", cpu:"i386", reference:"flash-plugin-9.0.289.0-2.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
