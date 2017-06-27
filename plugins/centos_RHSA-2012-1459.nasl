#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1459 and 
# CentOS Errata and Security Advisory 2012:1459 respectively.
#

include("compat.inc");

if (description)
{
  script_id(62911);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/29 00:03:03 $");

  script_cve_id("CVE-2011-2486");
  script_bugtraq_id(48487);
  script_xref(name:"RHSA", value:"2012:1459");

  script_name(english:"CentOS 6 : nspluginwrapper (CESA-2012:1459)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nspluginwrapper packages that fix one security issue and one
bug are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

nspluginwrapper is a utility which allows 32-bit plug-ins to run in a
64-bit browser environment (a common example is Adobe's browser
plug-in for presenting proprietary Flash files embedded in web pages).
It includes the plug-in viewer and a tool for managing plug-in
installations and updates.

It was not possible for plug-ins wrapped by nspluginwrapper to
discover whether the browser was running in Private Browsing mode.
This flaw could lead to plug-ins wrapped by nspluginwrapper using
normal mode while they were expected to run in Private Browsing mode.
(CVE-2011-2486)

This update also fixes the following bug :

* When using the Adobe Reader web browser plug-in provided by the
acroread-plugin package on a 64-bit system, opening Portable Document
Format (PDF) files in Firefox could cause the plug-in to crash and a
black window to be displayed where the PDF should be. Firefox had to
be restarted to resolve the issue. This update implements a workaround
in nspluginwrapper to automatically handle the plug-in crash, so that
users no longer have to keep restarting Firefox. (BZ#869554)

All users of nspluginwrapper are advised to upgrade to these updated
packages, which upgrade nspluginwrapper to upstream version 1.4.4, and
correct these issues. After installing the update, Firefox must be
restarted for the changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-November/018992.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed3324eb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspluginwrapper package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspluginwrapper");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"nspluginwrapper-1.4.4-1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
