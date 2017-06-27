#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60209);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2006-7203", "CVE-2007-1353", "CVE-2007-2453", "CVE-2007-2525");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
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
"a flaw in the mount handling routine for 64-bit systems that allowed a
local user to cause denial of service (CVE-2006-7203, Important).

a flaw in the PPP over Ethernet implementation that allowed a remote
user to cause a denial of service (CVE-2007-2525, Important).

a flaw in the Bluetooth subsystem that allowed a local user to trigger
an information leak (CVE-2007-1353, Low).

a bug in the random number generator that prevented the manual seeding
of the entropy pool (CVE-2007-2453, Low).

In addition to the security issues described above, fixes for the
following have been included :

  - a race condition between ext3_link/unlink that could
    create an orphan inode list corruption.

  - a bug in the e1000 driver that could lead to a watchdog
    timeout panic."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0706&L=scientific-linux-errata&T=0&P=3077
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81b27123"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/14");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-8.1.6.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-8.1.6.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-8.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-8.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-8.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-8.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-8.1.6.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-8.1.6.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
