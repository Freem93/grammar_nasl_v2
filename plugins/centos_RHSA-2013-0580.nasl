#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0580 and 
# CentOS Errata and Security Advisory 2013:0580 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65031);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2012-5519");
  script_bugtraq_id(56494);
  script_osvdb_id(87635);
  script_xref(name:"RHSA", value:"2013:0580");

  script_name(english:"CentOS 5 / 6 : cups (CESA-2013:0580)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cups packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Common UNIX Printing System (CUPS) provides a portable printing
layer for Linux, UNIX, and similar operating systems.

It was discovered that CUPS administrative users (members of the
SystemGroups groups) who are permitted to perform CUPS configuration
changes via the CUPS web interface could manipulate the CUPS
configuration to gain unintended privileges. Such users could read or
write arbitrary files with the privileges of the CUPS daemon, possibly
allowing them to run arbitrary code with root privileges.
(CVE-2012-5519)

After installing this update, the ability to change certain CUPS
configuration directives remotely will be disabled by default. The
newly introduced ConfigurationChangeRestriction directive can be used
to enable the changing of the restricted directives remotely. Refer to
Red Hat Bugzilla bug 875898 for more details and the list of
restricted directives.

All users of cups are advised to upgrade to these updated packages,
which contain a backported patch to resolve this issue. After
installing this update, the cupsd daemon will be restarted
automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019261.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96041315"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019616.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9d98dae9"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-March/000811.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?545ac1b0"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cups packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-lpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cups-php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"cups-1.3.7-30.el5_9.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-devel-1.3.7-30.el5_9.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-libs-1.3.7-30.el5_9.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cups-lpd-1.3.7-30.el5_9.3")) flag++;

if (rpm_check(release:"CentOS-6", reference:"cups-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-devel-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-libs-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-lpd-1.4.2-50.el6_4.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"cups-php-1.4.2-50.el6_4.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
