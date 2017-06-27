#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2764. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70128);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-4296");
  script_bugtraq_id(62510);
  script_osvdb_id(97506);
  script_xref(name:"DSA", value:"2764");

  script_name(english:"Debian DSA-2764-1 : libvirt - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Daniel P. Berrange discovered that incorrect memory handling in the
remoteDispatchDomainMemoryStats() function could lead to denial of
service.

The oldstable distribution (squeeze) is not affected."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libvirt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2764"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libvirt packages.

For the stable distribution (wheezy), this problem has been fixed in
version 0.9.12-11+deb7u4. This update also includes some non-security
related bugfixes scheduled for the upcoming Wheezy 7.2 point release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");
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
if (deb_check(release:"7.0", prefix:"libvirt-bin", reference:"0.9.12-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libvirt-dev", reference:"0.9.12-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libvirt-doc", reference:"0.9.12-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libvirt0", reference:"0.9.12-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libvirt0-dbg", reference:"0.9.12-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"python-libvirt", reference:"0.9.12-11+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
