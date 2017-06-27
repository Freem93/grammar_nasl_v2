#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60398);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2007-3919", "CVE-2007-5730", "CVE-2008-0928", "CVE-2008-1943", "CVE-2008-1944", "CVE-2008-2004");

  script_name(english:"Scientific Linux Security Update : xen on SL5.x i386/x86_64");
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
"Note: Troy Dawson has tested this update on a machine hosting both
paravirtualized and fully virtualized machines, both 32 bit and 64
bit. He did the update while all the machines were running, none of
them had any problems. He also tried stopping, starting, and rebooting
several of the machines. All without any problems. We tell you this
because updating the xen package, while running virtual machines, can
make you a little nervous.

These updated packages fix the following security issues :

Daniel P. Berrange discovered that the hypervisor's para-virtualized
framebuffer (PVFB) backend failed to validate the format of messages
serving to update the contents of the framebuffer. This could allow a
malicious user to cause a denial of service, or compromise the
privileged domain (Dom0). (CVE-2008-1944)

Markus Armbruster discovered that the hypervisor's para-virtualized
framebuffer (PVFB) backend failed to validate the frontend's
framebuffer description. This could allow a malicious user to cause a
denial of service, or to use a specially crafted frontend to
compromise the privileged domain (Dom0). (CVE-2008-1943)

Chris Wright discovered a security vulnerability in the QEMU block
format auto-detection, when running fully-virtualized guests. Such
fully-virtualized guests, with a raw formatted disk image, were able
to write a header to that disk image describing another format. This
could allow such guests to read arbitrary files in their hypervisor's
host. (CVE-2008-2004)

Ian Jackson discovered a security vulnerability in the QEMU block
device drivers backend. A guest operating system could issue a block
device request and read or write arbitrary memory locations, which
could lead to privilege escalation. (CVE-2008-0928)

Tavis Ormandy found that QEMU did not perform adequate sanity-checking
of data received via the 'net socket listen' option. A malicious local
administrator of a guest domain could trigger this flaw to potentially
execute arbitrary code outside of the domain. (CVE-2007-5730)

Steve Kemp discovered that the xenbaked daemon and the XenMon utility
communicated via an insecure temporary file. A malicious local
administrator of a guest domain could perform a symbolic link attack,
causing arbitrary files to be truncated. (CVE-2007-3919)

As well, in the previous xen packages, it was possible for Dom0 to
fail to flush data from a fully-virtualized guest to disk, even if the
guest explicitly requested the flush. This could cause data integrity
problems on the guest. In these updated packages, Dom0 always respects
the request to flush to disk."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0805&L=scientific-linux-errata&T=0&P=631
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a953235f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen, xen-devel and / or xen-libs packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(59, 119, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/13");
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
if (rpm_check(release:"SL5", reference:"xen-3.0.3-41.el5_1.5")) flag++;
if (rpm_check(release:"SL5", reference:"xen-devel-3.0.3-41.el5_1.5")) flag++;
if (rpm_check(release:"SL5", reference:"xen-libs-3.0.3-41.el5_1.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
