#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0086 and 
# CentOS Errata and Security Advisory 2007:0086 respectively.
#

include("compat.inc");

if (description)
{
  script_id(24674);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:16 $");

  script_cve_id("CVE-2007-1007");
  script_bugtraq_id(22613);
  script_osvdb_id(32083);
  script_xref(name:"RHSA", value:"2007:0086");

  script_name(english:"CentOS 3 / 4 : gnomemeeting (CESA-2007:0086)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnomemeeting packages that fix a security issue are now
available for Red Hat Enterprise Linux.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

GnomeMeeting is a tool to communicate with video and audio over the
Internet.

A format string flaw was found in the way GnomeMeeting processes
certain messages. If a user is running GnomeMeeting, a remote attacker
who can connect to GnomeMeeting could trigger this flaw and
potentially execute arbitrary code with the privileges of the user.
(CVE-2007-1007)

Users of GnomeMeeting should upgrade to these updated packages which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013549.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f1aff29"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013550.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?281d360f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013551.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d891bbb9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013552.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c77fae5c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013556.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2f01b723"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013557.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc624397"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnomemeeting package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnomemeeting");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"gnomemeeting-0.96.0-5")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gnomemeeting-1.0.2-9")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");