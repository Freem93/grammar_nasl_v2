#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(87580);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/29 14:44:44 $");

  script_cve_id("CVE-2015-5273", "CVE-2015-5287", "CVE-2015-5302");

  script_name(english:"Scientific Linux Security Update : abrt and libreport on SL7.x x86_64");
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
"It was found that the ABRT debug information installer (abrt-action-
install-debuginfo-to-abrt-cache) did not use temporary directories in
a secure way. A local attacker could use the flaw to create symbolic
links and files at arbitrary locations as the abrt user.
(CVE-2015-5273)

It was discovered that the kernel-invoked coredump processor provided
by ABRT did not handle symbolic links correctly when writing core
dumps of ABRT programs to the ABRT dump directory (/var/spool/abrt). A
local attacker with write access to an ABRT problem directory could
use this flaw to escalate their privileges. (CVE-2015-5287)

It was found that ABRT may have exposed unintended information to Red
Hat Bugzilla during crash reporting. A bug in the libreport library
caused changes made by a user in files included in a crash report to
be discarded. As a result, Red Hat Bugzilla attachments may contain
data that was not intended to be made public, including host names, IP
addresses, or command line options. (CVE-2015-5302)

This flaw did not affect default installations of ABRT on Scientific
Linux as they do not post data to Red Hat Bugzilla. This feature can
however be enabled, potentially impacting modified ABRT instances.
With this update Scientific Linux will no longer publish the
rhel-autoreport tools."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=16912
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2601e33b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-ccpp-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-kerneloops-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-pstoreoops-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-python-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-upload-watch-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-vmcore-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-addon-xorg-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-cli-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-console-notification-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-dbus-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-debuginfo-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-desktop-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-devel-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-gui-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-gui-devel-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-gui-libs-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-libs-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-python-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", reference:"abrt-python-doc-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-retrace-client-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"abrt-tui-2.1.11-35.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-anaconda-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-cli-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-compat-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-debuginfo-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-devel-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-filesystem-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-gtk-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-gtk-devel-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-newt-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-bugzilla-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-kerneloops-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-logger-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-mailx-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-reportuploader-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-rhtsupport-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-plugin-ureport-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-python-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-rhel-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-rhel-anaconda-bugzilla-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-rhel-bugzilla-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-web-2.1.11-31.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreport-web-devel-2.1.11-31.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
