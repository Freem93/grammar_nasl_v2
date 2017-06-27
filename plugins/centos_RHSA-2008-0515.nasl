#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0515 and 
# CentOS Errata and Security Advisory 2008:0515 respectively.
#

include("compat.inc");

if (description)
{
  script_id(33110);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2008-1108", "CVE-2008-1109");
  script_bugtraq_id(29527);
  script_osvdb_id(46005);
  script_xref(name:"RHSA", value:"2008:0515");

  script_name(english:"CentOS 4 : evolution28 (CESA-2008:0515)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution28 packages that address two buffer overflow
vulnerabilities are now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Evolution is the integrated collection of e-mail, calendaring, contact
management, communications and personal information management (PIM)
tools for the GNOME desktop environment.

A flaw was found in the way Evolution parsed iCalendar timezone
attachment data. If the Itip Formatter plug-in was disabled and a user
opened a mail with a carefully crafted iCalendar attachment, arbitrary
code could be executed as the user running Evolution. (CVE-2008-1108)

Note: the Itip Formatter plug-in, which allows calendar information
(attachments with a MIME type of 'text/calendar') to be displayed as
part of the e-mail message, is enabled by default.

A heap-based buffer overflow flaw was found in the way Evolution
parsed iCalendar attachments with an overly long 'DESCRIPTION'
property string. If a user responded to a carefully crafted iCalendar
attachment in a particular way, arbitrary code could be executed as
the user running Evolution. (CVE-2008-1109).

The particular response required to trigger this vulnerability was as
follows :

1. Receive the carefully crafted iCalendar attachment. 2. Accept the
associated meeting. 3. Open the calender the meeting was in. 4. Reply
to the sender.

Red Hat would like to thank Alin Rad Pop of Secunia Research for
responsibly disclosing these issues.

All Evolution users should upgrade to these updated packages, which
contain backported patches which resolves these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014956.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?393dfe8d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014966.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b263507"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014967.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1c430c7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution28 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution28-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"evolution28-2.8.0-53.el4_6.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution28-devel-2.8.0-53.el4_6.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
