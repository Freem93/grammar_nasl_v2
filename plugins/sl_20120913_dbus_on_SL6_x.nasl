#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(62106);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/26 14:44:46 $");

  script_cve_id("CVE-2012-3524");

  script_name(english:"Scientific Linux Security Update : dbus on SL6.x i386/x86_64");
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
"It was discovered that the D-Bus library honored environment settings
even when running with elevated privileges. A local attacker could
possibly use this flaw to escalate their privileges, by setting
specific environment variables before running a setuid or setgid
application linked against the D-Bus library (libdbus).
(CVE-2012-3524)

Note: With this update, libdbus ignores environment variables when
used by setuid or setgid applications. The environment is not ignored
when an application gains privileges via file system capabilities;
however, no application shipped in Red Hat Enterprise Linux 6 gains
privileges via file system capabilities.

We would like to thank Sebastian Krahmer of the SUSE Security Team for
reporting this issue.

For the update to take effect, all running instances of dbus-daemon
and all running applications using the libdbus library must be
restarted, or the system rebooted."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=2289
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00e5c6b6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"dbus-1.2.24-7.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"dbus-devel-1.2.24-7.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"dbus-doc-1.2.24-7.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"dbus-libs-1.2.24-7.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"dbus-x11-1.2.24-7.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
