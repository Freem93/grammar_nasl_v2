#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0197 and 
# CentOS Errata and Security Advisory 2008:0197 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43679);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/03/30 13:45:13 $");

  script_cve_id("CVE-2008-0887");
  script_bugtraq_id(28575);
  script_osvdb_id(43986);
  script_xref(name:"RHSA", value:"2008:0197");

  script_name(english:"CentOS 5 : gnome-screensaver (CESA-2008:0197)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated gnome-screensaver package that fixes a security flaw is now
available for Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

gnome-screensaver is the GNOME project's official screen saver
program.

A flaw was found in the way gnome-screensaver verified user passwords.
When a system used a remote directory service for login credentials, a
local attacker able to cause a network outage could cause
gnome-screensaver to crash, unlocking the screen. (CVE-2008-0887)

Users of gnome-screensaver should upgrade to this updated package,
which contains a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014876.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f98adfcc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-April/014877.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5756f755"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnome-screensaver package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnome-screensaver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"gnome-screensaver-2.16.1-5.el5_1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
