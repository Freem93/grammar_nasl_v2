#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3118. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80361);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/07/14 13:43:55 $");

  script_cve_id("CVE-2014-9221");
  script_osvdb_id(116704);
  script_xref(name:"DSA", value:"3118");

  script_name(english:"Debian DSA-3118-1 : strongswan - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mike Daskalakis reported a denial of service vulnerability in charon,
the IKEv2 daemon for strongSwan, an IKE/IPsec suite used to establish
IPsec protected links.

The bug can be triggered by an IKEv2 Key Exchange (KE) payload that
contains the Diffie-Hellman (DH) group 1025. This identifier is from
the private-use range and only used internally by libtls for DH groups
with custom generator and prime (MODP_CUSTOM). As such the
instantiated method expects that these two values are passed to the
constructor. This is not the case when a DH object is created based on
the group in the KE payload. Therefore, an invalid pointer is
dereferenced later, which causes a segmentation fault.

This means that the charon daemon can be crashed with a single
IKE_SA_INIT message containing such a KE payload. The starter process
should restart the daemon after that, but this might increase load on
the system. Remote code execution is not possible due to this issue,
nor is IKEv1 affected in charon or pluto."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/strongswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3118"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the strongswan packages.

For the stable distribution (wheezy), this problem has been fixed in
version 4.5.2-1.5+deb7u6.

For the upcoming stable distribution (jessie), this problem has been
fixed in version 5.2.1-5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libstrongswan", reference:"4.5.2-1.5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan", reference:"4.5.2-1.5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-dbg", reference:"4.5.2-1.5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-ikev1", reference:"4.5.2-1.5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-ikev2", reference:"4.5.2-1.5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-nm", reference:"4.5.2-1.5+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"strongswan-starter", reference:"4.5.2-1.5+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
