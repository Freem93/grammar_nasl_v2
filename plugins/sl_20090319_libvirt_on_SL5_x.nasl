#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60551);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-5086", "CVE-2009-0036");

  script_name(english:"Scientific Linux Security Update : libvirt on SL5.x i386/x86_64");
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
"The libvirtd daemon was discovered to not properly check user
connection permissions before performing certain privileged actions,
such as requesting migration of an unprivileged guest domain to
another system. A local user able to establish a read-only connection
to libvirtd could use this flaw to perform actions that should be
restricted to read-write connections. (CVE-2008-5086)

libvirt_proxy, a setuid helper application allowing non-privileged
users to communicate with the hypervisor, was discovered to not
properly validate user requests. Local users could use this flaw to
cause a stack-based buffer overflow in libvirt_proxy, possibly
allowing them to run arbitrary code with root privileges.
(CVE-2009-0036)

After installing the update, libvirtd must be restarted manually (for
example, by issuing a 'service libvirtd restart' command) for this
change to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0903&L=scientific-linux-errata&T=0&P=2112
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dc34027"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libvirt, libvirt-devel and / or libvirt-python
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/19");
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
if (rpm_check(release:"SL5", reference:"libvirt-0.3.3-14.el5_3.1")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-devel-0.3.3-14.el5_3.1")) flag++;
if (rpm_check(release:"SL5", reference:"libvirt-python-0.3.3-14.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
