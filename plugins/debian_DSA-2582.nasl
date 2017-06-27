#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2582. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63188);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2011-3131", "CVE-2012-4535", "CVE-2012-4537", "CVE-2012-4538", "CVE-2012-4539", "CVE-2012-5510", "CVE-2012-5513", "CVE-2012-5514", "CVE-2012-5515");
  script_bugtraq_id(49146, 56498, 56794, 56798, 56803);
  script_osvdb_id(74629, 87298, 87305, 87306, 87307, 88127, 88128, 88130, 88131);
  script_xref(name:"DSA", value:"2582");

  script_name(english:"Debian DSA-2582-1 : xen - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple denial of service vulnerabilities have been discovered in the
Xen Hypervisor. One of the issue (CVE-2012-5513 ) could even lead to
privilege escalation from guest to host.

Some of the recently published Xen Security Advisories ( XSA 25and 28)
are not fixed by this update and should be fixed in a future release.

  - CVE-2011-3131 ( XSA 5): DoS using I/OMMU faults from
    PCI-passthrough guest
    A VM that controls a PCI[E] device directly can cause it
    to issue DMA requests to invalid addresses. Although
    these requests are denied by the I/OMMU, the hypervisor
    needs to handle the interrupt and clear the error from
    the I/OMMU, and this can be used to live-lock a CPU and
    potentially hang the host.

  - CVE-2012-4535 ( XSA 20): Timer overflow DoS
    vulnerability

    A guest which sets a VCPU with an inappropriate deadline
    can cause an infinite loop in Xen, blocking the affected
    physical CPU indefinitely.

  - CVE-2012-4537 ( XSA 22): Memory mapping failure DoS
    vulnerability

    When set_p2m_entry fails, Xen's internal data structures
    (the p2m and m2p tables) can get out of sync. This
    failure can be triggered by unusual guest behaviour
    exhausting the memory reserved for the p2m table. If it
    happens, subsequent guest-invoked memory operations can
    cause Xen to fail an assertion and crash.

  - CVE-2012-4538 ( XSA 23): Unhooking empty PAE entries DoS
    vulnerability

    The HVMOP_pagetable_dying hypercall does not correctly
    check the caller's pagetable state, leading to a
    hypervisor crash.

  - CVE-2012-4539 ( XSA 24): Grant table hypercall infinite
    loop DoS vulnerability

    Due to inappropriate duplicate use of the same loop
    control variable, passing bad arguments to
    GNTTABOP_get_status_frames can cause an infinite loop in
    the compat hypercall handler.

  - CVE-2012-5510 ( XSA 26): Grant table version switch list
    corruption vulnerability

    Downgrading the grant table version of a guest involves
    freeing its status pages. This freeing was incomplete -
    the page(s) are freed back to the allocator, but not
    removed from the domain's tracking list. This would
    cause list corruption, eventually leading to a
    hypervisor crash.

  - CVE-2012-5513 ( XSA 29): XENMEM_exchange may overwrite
    hypervisor memory

    The handler for XENMEM_exchange accesses guest memory
    without range checking the guest provided addresses,
    thus allowing these accesses to include the hypervisor
    reserved range.

  A malicious guest administrator can cause Xen to crash. If the out
  of address space bounds access does not lead to a crash, a carefully
  crafted privilege escalation cannot be excluded, even though the
  guest doesn't itself control the values written.

  - CVE-2012-5514 ( XSA 30): Broken error handling in
    guest_physmap_mark_populate_on_demand()

    guest_physmap_mark_populate_on_demand(), before carrying
    out its actual operation, checks that the subject GFNs
    are not in use. If that check fails, the code prints a
    message and bypasses the gfn_unlock() matching the
    gfn_lock() carried out before entering the loop. A
    malicious guest administrator can then use it to cause
    Xen to hang.

  - CVE-2012-5515 ( XSA 31): Several memory hypercall
    operations allow invalid extent order values

    Allowing arbitrary extent_order input values for
    XENMEM_decrease_reservation, XENMEM_populate_physmap,
    and XENMEM_exchange can cause arbitrarily long time
    being spent in loops without allowing vital other code
    to get a chance to execute. This may also cause
    inconsistent state resulting at the completion of these
    hypercalls."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-11/msg00006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-12/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-devel/2011-08/msg00450.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4535"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-11/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-11/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4538"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-11/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-11/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5510"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-12/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5513"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-12/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5514"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-12/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5515"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.xen.org/archives/html/xen-announce/2012-12/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/xen"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2582"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xen packages.

For the stable distribution (squeeze), these problems have been fixed
in version 4.0.1-5.5."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"6.0", prefix:"libxen-dev", reference:"4.0.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"libxenstore3.0", reference:"4.0.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"xen-docs-4.0", reference:"4.0.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"xen-hypervisor-4.0-amd64", reference:"4.0.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"xen-hypervisor-4.0-i386", reference:"4.0.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"xen-utils-4.0", reference:"4.0.1-5.5")) flag++;
if (deb_check(release:"6.0", prefix:"xenstore-utils", reference:"4.0.1-5.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
