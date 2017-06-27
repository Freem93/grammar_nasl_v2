#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2893. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73293);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/16 15:43:11 $");

  script_cve_id("CVE-2013-2053", "CVE-2013-6466");
  script_bugtraq_id(59838, 65155);
  script_xref(name:"DSA", value:"2893");

  script_name(english:"Debian DSA-2893-1 : openswan - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were fixed in Openswan, an IKE/IPsec
implementation for Linux.

  - CVE-2013-2053
    During an audit of Libreswan (with which Openswan shares
    some code), Florian Weimer found a remote buffer
    overflow in the atodn() function. This vulnerability can
    be triggered when Opportunistic Encryption (OE) is
    enabled and an attacker controls the PTR record of a
    peer IP address. Authentication is not needed to trigger
    the vulnerability.

  - CVE-2013-6466
    Iustina Melinte found a vulnerability in Libreswan which
    also applies to the Openswan code. By carefully crafting
    IKEv2 packets, an attacker can make the pluto daemon
    dereference non-received IKEv2 payload, leading to the
    daemon crash. Authentication is not needed to trigger
    the vulnerability.

Patches were originally written to fix the vulnerabilities in
Libreswan, and have been ported to Openswan by Paul Wouters from the
Libreswan Project.

Since the Openswan package is not maintained anymore in the Debian
distribution and is not available in testing and unstable suites, it
is recommended for IKE/IPsec users to switch to a supported
implementation like strongSwan."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-2053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6466"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2893"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openswan packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 2.6.28+dfsg-5+squeeze2.

For the stable distribution (wheezy), these problems have been fixed
in version 2.6.37-3.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/02");
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
if (deb_check(release:"6.0", prefix:"openswan", reference:"2.6.28+dfsg-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openswan-dbg", reference:"2.6.28+dfsg-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openswan-doc", reference:"2.6.28+dfsg-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openswan-modules-dkms", reference:"2.6.28+dfsg-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openswan-modules-source", reference:"2.6.28+dfsg-5+squeeze2")) flag++;
if (deb_check(release:"7.0", prefix:"openswan", reference:"2.6.37-3.1")) flag++;
if (deb_check(release:"7.0", prefix:"openswan-dbg", reference:"2.6.37-3.1")) flag++;
if (deb_check(release:"7.0", prefix:"openswan-doc", reference:"2.6.37-3.1")) flag++;
if (deb_check(release:"7.0", prefix:"openswan-modules-dkms", reference:"2.6.37-3.1")) flag++;
if (deb_check(release:"7.0", prefix:"openswan-modules-source", reference:"2.6.37-3.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
