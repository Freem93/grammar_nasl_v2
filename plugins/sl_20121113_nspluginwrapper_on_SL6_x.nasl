#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(62919);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/11/20 11:51:03 $");

  script_cve_id("CVE-2011-2486");

  script_name(english:"Scientific Linux Security Update : nspluginwrapper on SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was not possible for plug-ins wrapped by nspluginwrapper to
discover whether the browser was running in Private Browsing mode.
This flaw could lead to plug-ins wrapped by nspluginwrapper using
normal mode while they were expected to run in Private Browsing mode.
(CVE-2011-2486)

This update also fixes the following bug :

  - When using the Adobe Reader(tm) web browser plug-in
    provided by the acroread-plugin package on a 64-bit
    system, opening Portable Document Format (PDF) files in
    Firefox could cause the plug-in to crash and a black
    window to be displayed where the PDF should be. Firefox
    had to be restarted to resolve the issue. This update
    implements a workaround in nspluginwrapper to
    automatically handle the plug-in crash, so that users no
    longer have to keep restarting Firefox.

This will update nspluginwrapper to upstream version 1.4.4.

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1211&L=scientific-linux-errata&T=0&P=1198
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52d693b8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nspluginwrapper package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/14");
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
if (rpm_check(release:"SL6", reference:"nspluginwrapper-1.4.4-1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
