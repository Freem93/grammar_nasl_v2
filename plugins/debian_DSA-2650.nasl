#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2650. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65586);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2013-1766");
  script_bugtraq_id(58178);
  script_osvdb_id(90670);
  script_xref(name:"DSA", value:"2650");

  script_name(english:"Debian DSA-2650-2 : libvirt - files and device nodes ownership change to kvm group");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Bastian Blank discovered that libvirtd, a daemon for management of
virtual machines, network and storage, would change ownership of
devices files so they would be owned by user 'libvirt-qemu' and group
'kvm', which is a general purpose group not specific to libvirt,
allowing unintended write access to those devices and files for the
kvm group members."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=701649"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2650"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvirt packages.

For the stable distribution (squeeze), this problem has been fixed in
version 0.8.3-5+squeeze5."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/17");
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
if (deb_check(release:"6.0", prefix:"libvirt-bin", reference:"0.8.3-5+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libvirt-dev", reference:"0.8.3-5+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libvirt-doc", reference:"0.8.3-5+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libvirt0", reference:"0.8.3-5+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libvirt0-dbg", reference:"0.8.3-5+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"python-libvirt", reference:"0.8.3-5+squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
