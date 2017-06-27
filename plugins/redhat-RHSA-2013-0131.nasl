#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0131. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63412);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2009-2473");
  script_bugtraq_id(36080);
  script_osvdb_id(57423);
  script_xref(name:"RHSA", value:"2013:0131");

  script_name(english:"RHEL 5 : gnome-vfs2 (RHSA-2013:0131)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gnome-vfs2 packages that fix one security issue and several
bugs are now available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The gnome-vfs2 packages provide the GNOME Virtual File System, which
is the foundation of the Nautilus file manager. neon is an HTTP and
WebDAV client library embedded in the gnome-vfs2 packages.

A denial of service flaw was found in the neon Extensible Markup
Language (XML) parser. Visiting a malicious DAV server with an
application using gnome-vfs2 (such as Nautilus) could possibly cause
the application to consume an excessive amount of CPU and memory.
(CVE-2009-2473)

This update also fixes the following bugs :

* When extracted from the Uniform Resource Identifier (URI),
gnome-vfs2 returned escaped file paths. If a path, as stored in the
URI, contained non-ASCII characters or ASCII characters which are
parsed as something other than a file path (for example, spaces), the
escaped path was inaccurate. Consequently, files with the described
type of URI could not be processed. With this update, gnome-vfs2
properly unescapes paths that are required for a system call. As a
result, these paths are parsed properly. (BZ#580855)

* In certain cases, the trash info file was populated by foreign
entries, pointing to live data. Emptying the trash caused an
accidental deletion of valuable data. With this update, a workaround
has been applied in order to prevent the deletion. As a result, the
accidental data loss is prevented, however further information is
still gathered to fully fix this problem. (BZ#586015)

* Due to a wrong test checking for a destination file system, the
Nautilus file manager failed to delete a symbolic link to a folder
which was residing in another file system. With this update, a special
test has been added. As a result, a symbolic link pointing to another
file system can be trashed or deleted properly. (BZ#621394)

* Prior to this update, when directories without a read permission
were marked for copy, the Nautilus file manager skipped these
unreadable directories without notification. With this update,
Nautilus displays an error message and properly informs the user about
the aforementioned problem. (BZ#772307)

* Previously, gnome-vfs2 used the stat() function calls for every file
on the MultiVersion File System (MVFS), used for example by IBM
Rational ClearCase. This behavior significantly slowed down file
operations. With this update, the unnecessary stat() operations have
been limited. As a result, gnome-vfs2 user interfaces, such as
Nautilus, are more responsive. (BZ#822817)

All gnome-vfs2 users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-2473.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0131.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-vfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-vfs2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gnome-vfs2-smb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0131";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", reference:"gnome-vfs2-2.16.2-10.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"gnome-vfs2-debuginfo-2.16.2-10.el5")) flag++;
  if (rpm_check(release:"RHEL5", reference:"gnome-vfs2-devel-2.16.2-10.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"gnome-vfs2-smb-2.16.2-10.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"gnome-vfs2-smb-2.16.2-10.el5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"gnome-vfs2-smb-2.16.2-10.el5")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-vfs2 / gnome-vfs2-debuginfo / gnome-vfs2-devel / etc");
  }
}
