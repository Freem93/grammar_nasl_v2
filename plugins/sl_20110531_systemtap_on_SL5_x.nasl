#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61061);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:26 $");

  script_cve_id("CVE-2011-1769");

  script_name(english:"Scientific Linux Security Update : systemtap on SL5.x i386/x86_64");
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
"SystemTap is an instrumentation system for systems running the Linux
kernel, version 2.6. Developers can write scripts to collect data on
the operation of the system.

A divide-by-zero flaw was found in the way SystemTap handled malformed
debugging information in DWARF format. When SystemTap unprivileged
mode was enabled, an unprivileged user in the stapusr group could use
this flaw to crash the system. Additionally, a privileged user (root,
or a member of the stapdev group) could trigger this flaw when tricked
into instrumenting a specially crafted ELF binary, even when
unprivileged mode was not enabled. (CVE-2011-1769)

SystemTap users should upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1106&L=scientific-linux-errata&T=0&P=1141
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b89345f5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
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
if (rpm_check(release:"SL5", reference:"systemtap-1.3-4.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-client-1.3-4.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-debuginfo-1.3-4.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-initscript-1.3-4.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-runtime-1.3-4.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-sdt-devel-1.3-4.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-server-1.3-4.el5_6.1")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-testsuite-1.3-4.el5_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
