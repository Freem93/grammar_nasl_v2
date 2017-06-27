#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3038. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77921);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:48:48 $");

  script_cve_id("CVE-2014-0179", "CVE-2014-3633");
  script_bugtraq_id(67289);
  script_xref(name:"DSA", value:"3038");

  script_name(english:"Debian DSA-3038-1 : libvirt - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Libvirt, a virtualisation
abstraction library. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2014-0179
    Richard Jones and Daniel P. Berrange found that libvirt
    passes the XML_PARSE_NOENT flag when parsing XML
    documents using the libxml2 library, in which case all
    XML entities in the parsed documents are expanded. A
    user able to force libvirtd to parse an XML document
    with an entity pointing to a special file that blocks on
    read access could use this flaw to cause libvirtd to
    hang indefinitely, resulting in a denial of service on
    the system.

  - CVE-2014-3633
    Luyao Huang of Red Hat found that the qemu
    implementation of virDomainGetBlockIoTune computed an
    index into the array of disks for the live definition,
    then used it as the index into the array of disks for
    the persistent definition, which could result into an
    out-of-bounds read access in qemuDomainGetBlockIoTune().

  A remote attacker able to establish a read-only connection to
  libvirtd could use this flaw to crash libvirtd or, potentially, leak
  memory from the libvirtd process."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=762203"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3038"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvirt packages.

For the stable distribution (wheezy), these problems have been fixed
in version 0.9.12.3-1+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libvirt-bin", reference:"0.9.12.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libvirt-dev", reference:"0.9.12.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libvirt-doc", reference:"0.9.12.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libvirt0", reference:"0.9.12.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libvirt0-dbg", reference:"0.9.12.3-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"python-libvirt", reference:"0.9.12.3-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
