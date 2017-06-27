#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61084);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2011-2520");

  script_name(english:"Scientific Linux Security Update : system-config-firewall on SL6.x i386/x86_64");
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
"system-config-firewall is a graphical user interface for basic
firewall setup.

It was found that system-config-firewall used the Python pickle module
in an insecure way when sending data (via D-Bus) to the privileged
back-end mechanism. A local user authorized to configure firewall
rules using system-config-firewall could use this flaw to execute
arbitrary code with root privileges, by sending a specially crafted
serialized object. (CVE-2011-2520)

This erratum updates system-config-firewall to use JSON (JavaScript
Object Notation) for data exchange, instead of pickle. Therefore, an
updated version of system-config-printer that uses this new
communication data format is also provided in this erratum.

Users of system-config-firewall are advised to upgrade to these
updated packages, which contain a backported patch to resolve this
issue. Running instances of system-config-firewall must be restarted
before the utility will be able to communicate with its updated
back-end."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1107&L=scientific-linux-errata&T=0&P=1175
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab229333"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"system-config-firewall-1.2.27-3.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"system-config-firewall-base-1.2.27-3.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"system-config-firewall-tui-1.2.27-3.el6_1.3")) flag++;
if (rpm_check(release:"SL6", reference:"system-config-printer-1.1.16-17.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"system-config-printer-debuginfo-1.1.16-17.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"system-config-printer-libs-1.1.16-17.el6_1.2")) flag++;
if (rpm_check(release:"SL6", reference:"system-config-printer-udev-1.1.16-17.el6_1.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
