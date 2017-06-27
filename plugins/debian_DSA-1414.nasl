#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1414. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28337);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-6114", "CVE-2007-6117", "CVE-2007-6118", "CVE-2007-6120", "CVE-2007-6121");
  script_osvdb_id(40450);
  script_xref(name:"DSA", value:"1414");

  script_name(english:"Debian DSA-1414-1 : wireshark - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Wireshark
network traffic analyzer, which may lead to denial of service or
execution of arbitrary code. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2007-6114
    Stefan Esser discovered a buffer overflow in the SSL
    dissector.'Fabiodds' discovered a buffer overflow in the
    iSeries trace dissector.

  - CVE-2007-6117
    A programming error was discovered in the HTTP
    dissector, which may lead to denial of service.

  - CVE-2007-6118
    The MEGACO dissector could be tricked into resource
    exhaustion.

  - CVE-2007-6120
    The Bluetooth SDP dissector could be tricked into an
    endless loop.

  - CVE-2007-6121
    The RPC portmap dissector could be tricked into
    dereferencing a NULL pointer."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6117"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-6121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1414"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wireshark/ethereal packages.

For the old stable distribution (sarge), these problems have been
fixed in version 0.10.10-2sarge10. (In Sarge Wireshark used to be
called Ethereal). Updated packages for sparc and m68k will be provided
later.

For the stable distribution (etch), these problems have been fixed in
version 0.99.4-5.etch.1. Updated packages for sparc will be provided
later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wireshark");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"ethereal", reference:"0.10.10-2sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-common", reference:"0.10.10-2sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-dev", reference:"0.10.10-2sarge10")) flag++;
if (deb_check(release:"3.1", prefix:"tethereal", reference:"0.10.10-2sarge10")) flag++;
if (deb_check(release:"4.0", prefix:"ethereal", reference:"0.99.4-5.etch.1")) flag++;
if (deb_check(release:"4.0", prefix:"ethereal-common", reference:"0.99.4-5.etch.1")) flag++;
if (deb_check(release:"4.0", prefix:"ethereal-dev", reference:"0.99.4-5.etch.1")) flag++;
if (deb_check(release:"4.0", prefix:"tethereal", reference:"0.99.4-5.etch.1")) flag++;
if (deb_check(release:"4.0", prefix:"tshark", reference:"0.99.4-5.etch.1")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark", reference:"0.99.4-5.etch.1")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark-common", reference:"0.99.4-5.etch.1")) flag++;
if (deb_check(release:"4.0", prefix:"wireshark-dev", reference:"0.99.4-5.etch.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
