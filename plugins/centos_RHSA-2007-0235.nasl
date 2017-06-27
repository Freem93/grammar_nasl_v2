#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0235 and 
# CentOS Errata and Security Advisory 2007:0235 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67043);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_cve_id("CVE-2006-7108");
  script_xref(name:"RHSA", value:"2007:0235");

  script_name(english:"CentOS 4 : util-linux (CESA-2007:0235)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated util-linux package that corrects a security issue and fixes
several bugs is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The util-linux package contains a collection of basic system
utilities.

A flaw was found in the way the login process handled logins which did
not require authentication. Certain processes which conduct their own
authentication could allow a remote user to bypass intended access
policies which would normally be enforced by the login process.
(CVE-2006-7108)

This update also fixes the following bugs :

* The partx, addpart and delpart commands were not documented.

* The 'umount -l' command did not work on hung NFS mounts with cached
data.

* The mount command did not mount NFS V3 share where sec=none was
specified.

* The mount command did not read filesystem LABEL from unpartitioned
disks.

* The mount command did not recognize labels on VFAT filesystems.

* The fdisk command did not support 4096 sector size for the '-b'
option.

* The mount man page did not list option 'mand' or information about
/etc/mtab limitations.

All users of util-linux should upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2007-May/013710.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected util-linux package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:P/I:P/A:P");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:util-linux");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"util-linux-2.12a-16.EL4.25")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
