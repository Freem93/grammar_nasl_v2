#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(84113);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/07/06 13:45:35 $");

  script_cve_id("CVE-2015-1869", "CVE-2015-1870", "CVE-2015-3142", "CVE-2015-3147", "CVE-2015-3150", "CVE-2015-3151", "CVE-2015-3159", "CVE-2015-3315");

  script_name(english:"Scientific Linux Security Update : abrt on SL7.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that ABRT was vulnerable to multiple race condition and
symbolic link flaws. A local attacker could use these flaws to
potentially escalate their privileges on the system. (CVE-2015-3315)

It was discovered that the kernel-invoked coredump processor provided
by ABRT wrote core dumps to files owned by other system users. This
could result in information disclosure if an application crashed while
its current directory was a directory writable to by other users (such
as /tmp). (CVE-2015-3142)

It was discovered that the default event handling scripts installed by
ABRT did not handle symbolic links correctly. A local attacker with
write access to an ABRT problem directory could use this flaw to
escalate their privileges. (CVE-2015-1869)

It was found that the ABRT event scripts created a user-readable copy
of an sosreport file in ABRT problem directories, and included
excerpts of /var/log/messages selected by the user-controlled process
name, leading to an information disclosure. (CVE-2015-1870)

It was discovered that, when moving problem reports between certain
directories, abrt-handle-upload did not verify that the new problem
directory had appropriate permissions and did not contain symbolic
links. An attacker able to create a crafted problem report could use
this flaw to expose other parts of ABRT to attack, or to overwrite
arbitrary files on the system. (CVE-2015-3147)

Multiple directory traversal flaws were found in the abrt-dbus D-Bus
service. A local attacker could use these flaws to read and write
arbitrary files as the root user. (CVE-2015-3151)

It was discovered that the abrt-dbus D-Bus service did not properly
check the validity of the problem directory argument in the
ChownProblemDir, DeleteElement, and DeleteProblem methods. A local
attacker could use this flaw to take ownership of arbitrary files and
directories, or to delete files and directories as the root user.
(CVE-2015-3150)

It was discovered that the abrt-action-install-debuginfo-to-abrt-cache
helper program did not properly filter the process environment before
invoking abrt-action-install-debuginfo. A local attacker could use
this flaw to escalate their privileges on the system. (CVE-2015-3159)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1506&L=scientific-linux-errata&F=&S=&P=6189
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?008808f1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-ccpp-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-kerneloops-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-pstoreoops-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-python-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-upload-watch-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-vmcore-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-xorg-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-cli-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-console-notification-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-dbus-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-debuginfo-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-desktop-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-devel-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-gui-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-gui-devel-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-gui-libs-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-libs-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-python-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", reference:"abrt-python-doc-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-retrace-client-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-tui-2.1.11-22.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-anaconda-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-cli-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-compat-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-debuginfo-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-devel-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-filesystem-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-gtk-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-gtk-devel-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-newt-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-bugzilla-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-kerneloops-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-logger-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-mailx-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-reportuploader-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-rhtsupport-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-ureport-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-python-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-rhel-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-rhel-anaconda-bugzilla-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-rhel-bugzilla-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-web-2.1.11-23.sl7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-web-devel-2.1.11-23.sl7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
