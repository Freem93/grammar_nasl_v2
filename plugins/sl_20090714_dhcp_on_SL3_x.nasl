#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60615);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:25 $");

  script_cve_id("CVE-2009-0692", "CVE-2009-1893");

  script_name(english:"Scientific Linux Security Update : dhcp on SL3.x, SL4.x i386/x86_64");
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
"The Mandriva Linux Engineering Team discovered a stack-based buffer
overflow flaw in the ISC DHCP client. If the DHCP client were to
receive a malicious DHCP response, it could crash or execute arbitrary
code with the permissions of the client (root). (CVE-2009-0692)

An insecure temporary file use flaw was discovered in the DHCP
daemon's init script ('/etc/init.d/dhcpd'). A local attacker could use
this flaw to overwrite an arbitrary file with the output of the 'dhcpd
-t' command via a symbolic link attack, if a system administrator
executed the DHCP init script with the 'configtest', 'restart', or
'reload' option. (CVE-2009-1893)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0907&L=scientific-linux-errata&T=0&P=1009
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4209841b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dhclient, dhcp and / or dhcp-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"dhclient-3.0.1-10.2_EL3")) flag++;
if (rpm_check(release:"SL3", reference:"dhcp-3.0.1-10.2_EL3")) flag++;
if (rpm_check(release:"SL3", reference:"dhcp-devel-3.0.1-10.2_EL3")) flag++;

if (rpm_check(release:"SL4", reference:"dhclient-3.0.1-65.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"dhcp-3.0.1-65.el4_8.1")) flag++;
if (rpm_check(release:"SL4", reference:"dhcp-devel-3.0.1-65.el4_8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
