#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0324 and 
# CentOS Errata and Security Advisory 2011:0324 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53424);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/19 23:51:59 $");

  script_cve_id("CVE-2011-1018");
  script_bugtraq_id(46554);
  script_osvdb_id(71358);
  script_xref(name:"RHSA", value:"2011:0324");

  script_name(english:"CentOS 5 : logwatch (CESA-2011:0324)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated logwatch package that fixes one security issue is now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

Logwatch is a customizable log analysis system. Logwatch parses
through your system's logs for a given period of time and creates a
report analyzing areas that you specify, in as much detail as you
require.

A flaw was found in the way Logwatch processed log files. If an
attacker were able to create a log file with a malicious file name, it
could result in arbitrary code execution with the privileges of the
root user when that log file is analyzed by Logwatch. (CVE-2011-1018)

Users of logwatch should upgrade to this updated package, which
contains a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017365.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f08807d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017366.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76d1b7da"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected logwatch package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:logwatch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"logwatch-7.3-9.el5_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
