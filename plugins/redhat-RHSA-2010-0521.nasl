#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0521. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63938);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/05/02 17:31:16 $");

  script_cve_id("CVE-2010-0727");
  script_bugtraq_id(39101);
  script_xref(name:"RHSA", value:"2010:0521");

  script_name(english:"RHEL 5 : gfs-kmod (RHSA-2010:0521)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gfs-kmod packages that fix one security issue are now
available for Red Hat Enterprise Linux 5.4 Extended Update Support,
kernel release 2.6.18-164.19.1.el5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The gfs-kmod packages contain modules that provide the ability to
mount and use GFS file systems.

A flaw was found in the gfs_lock() implementation. The GFS locking
code could skip the lock operation for files that have the S_ISGID bit
(set-group-ID on execution) in their mode set. A local, unprivileged
user on a system that has a GFS file system mounted could use this
flaw to cause a kernel panic. (CVE-2010-0727)

These updated gfs-kmod packages are in sync with the latest kernel
(2.6.18-164.19.1.el5). The modules in earlier gfs-kmod packages failed
to load because they did not match the running kernel. It was possible
to force-load the modules. With this update, however, users no longer
need to.

Users are advised to upgrade to these latest gfs-kmod packages,
updated for use with the 2.6.18-164.19.1.el5 kernel, which contain a
backported patch to correct this issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0727.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0521.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kmod-gfs, kmod-gfs-PAE and / or kmod-gfs-xen
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-gfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-gfs-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kmod-gfs-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5.4");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/08");
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
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kmod-gfs-0.1.34-2.el5_4.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kmod-gfs-0.1.34-2.el5_4.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kmod-gfs-PAE-0.1.34-2.el5_4.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"i686", reference:"kmod-gfs-xen-0.1.34-2.el5_4.3")) flag++;
if (rpm_check(release:"RHEL5", sp:"4", cpu:"x86_64", reference:"kmod-gfs-xen-0.1.34-2.el5_4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
