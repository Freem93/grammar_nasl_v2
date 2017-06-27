#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61014);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:42:09 $");

  script_cve_id("CVE-2011-0997");

  script_name(english:"Scientific Linux Security Update : dhcp on SL4.x,SL5.x,SL6.x i386/x86_64");
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
"It was discovered that the DHCP client daemon, dhclient, did not
sufficiently sanitize certain options provided in DHCP server replies,
such as the client hostname. A malicious DHCP server could send such
an option with a specially crafted value to a DHCP client. If this
option's value was saved on the client system, and then later
insecurely evaluated by a process that assumes the option is trusted,
it could lead to arbitrary code execution with the privileges of that
process. (CVE-2011-0997)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1104&L=scientific-linux-errata&T=0&P=1068
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef7819c1"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/08");
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
if (rpm_check(release:"SL4", reference:"dhclient-3.0.1-67.el4")) flag++;
if (rpm_check(release:"SL4", reference:"dhcp-3.0.1-67.el4")) flag++;
if (rpm_check(release:"SL4", reference:"dhcp-devel-3.0.1-67.el4")) flag++;

if (rpm_check(release:"SL5", reference:"dhclient-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"dhcp-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"dhcp-devel-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"libdhcp4client-3.0.5-23.el5_6.4")) flag++;
if (rpm_check(release:"SL5", reference:"libdhcp4client-devel-3.0.5-23.el5_6.4")) flag++;

if (rpm_check(release:"SL6", reference:"dhclient-4.1.1-12.P1.el6_0.4")) flag++;
if (rpm_check(release:"SL6", reference:"dhcp-4.1.1-12.P1.el6_0.4")) flag++;
if (rpm_check(release:"SL6", reference:"dhcp-devel-4.1.1-12.P1.el6_0.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
