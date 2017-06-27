#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61336);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:57 $");

  script_cve_id("CVE-2011-4088", "CVE-2012-1106");

  script_name(english:"Scientific Linux Security Update : abrt, libreport, btparser, and python-meh on SL6.x i386/x86_64");
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
"ABRT (Automatic Bug Reporting Tool) is a tool to help users to detect
defects in applications and to create a bug report with all the
information needed by a maintainer to fix it. It uses a plug-in system
to extend its functionality. libreport provides an API for reporting
different problems in applications to different bug targets, such as
Bugzilla, FTP, and Trac.

The btparser utility is a backtrace parser and analyzer library, which
works with backtraces produced by the GNU Project Debugger. It can
parse a text file with a backtrace to a tree of C structures, allowing
to analyze the threads and frames of the backtrace and process them.

The python-meh package provides a python library for handling
exceptions.

If the C handler plug-in in ABRT was enabled (the abrt-addon-ccpp
package installed and the abrt-ccpp service running), and the sysctl
fs.suid_dumpable option was set to '2' (it is '0' by default), core
dumps of set user ID (setuid) programs were created with insecure
group ID permissions. This could allow local, unprivileged users to
obtain sensitive information from the core dump files of setuid
processes they would otherwise not be able to access. (CVE-2012-1106)

ABRT did not allow users to easily search the collected crash
information for sensitive data prior to submitting it. This could lead
to users unintentionally exposing sensitive information via the
submitted crash reports. This update adds functionality to search
across all the collected data. (CVE-2011-4088)

These updated packages include numerous bug fixes.

All users of abrt, libreport, btparser, and python-meh are advised to
upgrade to these updated packages, which correct these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1207&L=scientific-linux-errata&T=0&P=2933
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bf8cd67"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"abrt-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"abrt-addon-ccpp-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"abrt-addon-kerneloops-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"abrt-addon-python-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-addon-vmcore-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"abrt-cli-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-debuginfo-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"abrt-desktop-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-devel-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"abrt-gui-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"abrt-libs-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"abrt-tui-2.0.8-6.el6")) flag++;
if (rpm_check(release:"SL6", reference:"btparser-0.16-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"btparser-debuginfo-0.16-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"btparser-devel-0.16-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"btparser-python-0.16-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-cli-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-debuginfo-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-devel-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-gtk-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-gtk-devel-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-newt-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-bugzilla-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-kerneloops-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-logger-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-mailx-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-reportuploader-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-plugin-rhtsupport-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libreport-python-2.0.9-5.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-meh-0.12.1-3.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
