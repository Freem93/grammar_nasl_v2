#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0194 and 
# CentOS Errata and Security Advisory 2008:0194 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(43678);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2007-3919", "CVE-2007-5730", "CVE-2008-0928", "CVE-2008-1943", "CVE-2008-1944", "CVE-2008-2004");
  script_bugtraq_id(23731);
  script_osvdb_id(45411, 45412);
  script_xref(name:"RHSA", value:"2008:0194");

  script_name(english:"CentOS 5 : xen (CESA-2008:0194)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xen packages that fix several security issues and a bug are
now available for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The xen packages contain tools for managing the virtual machine
monitor in Red Hat Virtualization.

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
the request to flush to disk.

Users of xen are advised to upgrade to these updated packages, which
resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014903.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2008-May/014904.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xen packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59, 119, 200, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xen-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"xen-3.0.3-41.el5_1.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-devel-3.0.3-41.el5_1.5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xen-libs-3.0.3-41.el5_1.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
