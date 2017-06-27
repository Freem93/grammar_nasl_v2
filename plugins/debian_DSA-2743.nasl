#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2743. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69483);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-3077", "CVE-2013-4851", "CVE-2013-5209");
  script_bugtraq_id(61484, 61939, 61946);
  script_osvdb_id(95820, 96518, 96519);
  script_xref(name:"DSA", value:"2743");

  script_name(english:"Debian DSA-2743-1 : kfreebsd-9 - privilege escalation/information leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the FreeBSD kernel
that may lead to a privilege escalation or information leak. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2013-3077
    Clement Lecigne from the Google Security Team reported
    an integer overflow in computing the size of a temporary
    buffer in the IP multicast code, which can result in a
    buffer which is too small for the requested operation.
    An unprivileged process can read or write pages of
    memory which belong to the kernel. These may lead to
    exposure of sensitive information or allow privilege
    escalation.

  - CVE-2013-4851
    Rick Macklem, Christopher Key and Tim Zingelman reported
    that the FreeBSD kernel incorrectly uses client supplied
    credentials instead of the one configured in exports(5)
    when filling out the anonymous credential for a NFS
    export, when -network or -host restrictions are used at
    the same time. The remote client may supply privileged
    credentials (e.g. the root user) when accessing a file
    under the NFS share, which will bypass the normal access
    checks.

  - CVE-2013-5209
    Julian Seward and Michael Tuexen reported a kernel
    memory disclosure when initializing the SCTP state
    cookie being sent in INIT-ACK chunks, a buffer allocated
    from the kernel stack is not completely initialized.
    Fragments of kernel memory may be included in SCTP
    packets and transmitted over the network. For each SCTP
    session, there are two separate instances in which a
    4-byte fragment may be transmitted.

  This memory might contain sensitive information, such as portions of
  the file cache or terminal buffers. This information might be
  directly useful, or it might be leveraged to obtain elevated
  privileges in some way. For example, a terminal buffer might include
  an user-entered password."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-3077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-5209"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/kfreebsd-9"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2743"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kfreebsd-9 packages.

For the stable distribution (wheezy), these problems has been fixed in
version 9.0-10+deb70.3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kfreebsd-9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-486", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-686", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-686-smp", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-amd64", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-malta", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9-xen", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-486", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-686", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-686-smp", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-amd64", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-malta", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-headers-9.0-2-xen", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-486", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-686", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-686-smp", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-amd64", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-malta", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9-xen", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-486", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-686", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-686-smp", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-amd64", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-malta", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-image-9.0-2-xen", reference:"9.0-10+deb70.3")) flag++;
if (deb_check(release:"7.0", prefix:"kfreebsd-source-9.0", reference:"9.0-10+deb70.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
