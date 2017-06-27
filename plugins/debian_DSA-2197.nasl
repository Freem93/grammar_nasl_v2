#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2197. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52741);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:31:55 $");

  script_cve_id("CVE-2010-1674", "CVE-2010-1675");
  script_osvdb_id(71258, 71259);
  script_xref(name:"DSA", value:"2197");

  script_name(english:"Debian DSA-2197-1 : quagga - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It has been discovered that the Quagga routing daemon contains two
denial-of-service vulnerabilities in its BGP implementation :

  - CVE-2010-1674
    A crafted Extended Communities attribute triggers a NULL
    pointer dereference which causes the BGP daemon to
    crash. The crafted attributes are not propagated by the
    Internet core, so only explicitly configured direct
    peers are able to exploit this vulnerability in typical
    configurations.

  - CVE-2010-1675
    The BGP daemon resets BGP sessions when it encounters
    malformed AS_PATHLIMIT attributes, introducing a
    distributed BGP session reset vulnerability which
    disrupts packet forwarding. Such malformed attributes
    are propagated by the Internet core, and exploitation of
    this vulnerability is not restricted to directly
    configured BGP peers.

This security update removes AS_PATHLIMIT processing from the BGP
implementation, preserving the configuration statements for backwards
compatibility. (Standardization of this BGP extension was abandoned
long ago.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/quagga"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2197"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the quagga packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 0.99.10-1lenny5.

For the stable distribution (squeeze), these problems have been fixed
in version 0.99.17-2+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"quagga", reference:"0.99.10-1lenny5")) flag++;
if (deb_check(release:"6.0", prefix:"quagga", reference:"0.99.17-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"quagga-dbg", reference:"0.99.17-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"quagga-doc", reference:"0.99.17-2+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
