#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0159 and 
# CentOS Errata and Security Advisory 2008:0159 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43675);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/19 14:21:02 $");

  script_cve_id("CVE-2008-0595");
  script_bugtraq_id(28023);
  script_osvdb_id(43038);
  script_xref(name:"RHSA", value:"2008:0159");

  script_name(english:"CentOS 5 : dbus (CESA-2008:0159)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated dbus packages that fix an issue with circumventing the
security policy are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

D-Bus is a system for sending messages between applications. It is
used both for the system-wide message bus service, and as a
per-user-login-session messaging facility.

Havoc Pennington discovered a flaw in the way the dbus-daemon applies
its security policy. A user with the ability to connect to the
dbus-daemon may be able to execute certain method calls they should
normally not have permission to access. (CVE-2008-0595)

Red Hat does not ship any applications in Red Hat Enterprise Linux 5
that would allow a user to leverage this flaw to elevate their
privileges.

This flaw does not affect the version of D-Bus shipped in Red Hat
Enterprise Linux 4.

All users are advised to upgrade to these updated dbus packages, which
contain a backported patch and are not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014736.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c18b914f"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-March/014737.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?359a4050"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dbus packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/03");
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
if (rpm_check(release:"CentOS-5", reference:"dbus-1.0.0-6.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dbus-devel-1.0.0-6.3.el5_1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"dbus-x11-1.0.0-6.3.el5_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
