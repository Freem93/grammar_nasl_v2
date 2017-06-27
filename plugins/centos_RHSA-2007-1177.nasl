#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1177 and 
# CentOS Errata and Security Advisory 2007:1177 respectively.
#

include("compat.inc");

if (description)
{
  script_id(29754);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2007-6285");
  script_bugtraq_id(26970);
  script_osvdb_id(40442);
  script_xref(name:"RHSA", value:"2007:1177");

  script_name(english:"CentOS 4 : autofs5 (CESA-2007:1177)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated autofs5 technology preview packages that fix a security issue
are now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The autofs utility controls the operation of the automount daemon,
which automatically mounts file systems when you use them, and
unmounts them when you are not using them. This can include network
file systems and CD-ROMs. The autofs5 packages were made available as
a technology preview in Red Hat Enterprise Linux 4.6.

There was a security issue with the default configuration of autofs
version 5, whereby the entry for the '-hosts' map did not specify the
'nodev' mount option. A local user with control of a remote NFS server
could create special device files on the remote file system, that if
mounted using the default '-hosts' map, could allow the user to access
important system devices. (CVE-2007-6285)

This issue is similar to CVE-2007-5964, which fixed a missing 'nosuid'
mount option in autofs. Both the 'nodev' and 'nosuid' options should
be enabled to prevent a possible compromise of machine integrity.

Due to the fact that autofs always mounted '-hosts' map entries 'dev'
by default, autofs has now been altered to always use the 'nodev'
option when mounting from the default '-hosts' map. The 'dev' option
must be explicitly given in the master map entry to revert to the old
behavior. This change affects only the '-hosts' map which corresponds
to the '/net' entry in the default configuration.

All autofs5 users are advised to upgrade to these updated packages,
which resolve this issue.

Red Hat would like to thank Tim Baum for reporting this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014529.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e3f8b075"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014545.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c73d866"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-December/014546.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f547a22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected autofs5 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:autofs5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/24");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"autofs5-5.0.1-0.rc2.55.el4_6.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"autofs5-5.0.1-0.rc2.55.c4.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"autofs5-5.0.1-0.rc2.55.el4_6.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
