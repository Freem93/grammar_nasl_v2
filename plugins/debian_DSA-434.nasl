#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-434. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15271);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2013/05/18 00:11:35 $");

  script_cve_id("CVE-2004-0005", "CVE-2004-0006", "CVE-2004-0007", "CVE-2004-0008");
  script_bugtraq_id(9489);
  script_xref(name:"DSA", value:"434");

  script_name(english:"Debian DSA-434-1 : gaim - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stefan Esser discovered several security related problems in Gaim, a
multi-protocol instant messaging client. Not all of them are
applicable for the version in Debian stable, but affected the version
in the unstable distribution at least. The problems were grouped for
the Common Vulnerabilities and Exposures as follows :

  - CAN-2004-0005
    When the Yahoo Messenger handler decodes an octal value
    for email notification functions two different kinds of
    overflows can be triggered. When the MIME decoder
    decoded a quoted printable encoded string for email
    notification two other different kinds of overflows can
    be triggered. These problems only affect the version in
    the unstable distribution.

  - CAN-2004-0006

    When parsing the cookies within the HTTP reply header of
    a Yahoo web connection a buffer overflow can happen.
    When parsing the Yahoo Login Webpage the YMSG protocol
    overflows stack buffers if the web page returns
    oversized values. When splitting a URL into its parts a
    stack overflow can be caused. These problems only affect
    the version in the unstable distribution.

  When an oversized keyname is read from a Yahoo Messenger packet a
  stack overflow can be triggered. When Gaim is setup to use an HTTP
  proxy for connecting to the server a malicious HTTP proxy can
  exploit it. These problems affect all versions Debian ships.
  However, the connection to Yahoo doesn't work in the version in
  Debian stable.

  - CAN-2004-0007

    Internally data is copied between two tokens into a
    fixed size stack buffer without a size check. This only
    affects the version of gaim in the unstable
    distribution.

  - CAN-2004-0008

    When allocating memory for AIM/Oscar DirectIM packets an
    integer overflow can happen, resulting in a heap
    overflow. This only affects the version of gaim in the
    unstable distribution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-434"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gaim packages.

For the stable distribution (woody) these problems has been fixed in
version 0.58-2.4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gaim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"gaim", reference:"0.58-2.4")) flag++;
if (deb_check(release:"3.0", prefix:"gaim-common", reference:"0.58-2.4")) flag++;
if (deb_check(release:"3.0", prefix:"gaim-gnome", reference:"0.58-2.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
