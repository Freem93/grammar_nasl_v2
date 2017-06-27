#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-898-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99403);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/04/20 13:20:51 $");

  script_cve_id("CVE-2016-10324", "CVE-2016-10325", "CVE-2016-10326", "CVE-2017-7853");
  script_osvdb_id(144388, 155575, 155576, 155577);

  script_name(english:"Debian DLA-898-1 : libosip2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-10324 In libosip2 in GNU oSIP 4.1.0, a malformed SIP message
can lead to a heap buffer overflow in the osip_clrncpy() function
defined in osipparser2/osip_port.c.

CVE-2016-10325 In libosip2 in GNU oSIP 4.1.0, a malformed SIP message
can lead to a heap buffer overflow in the _osip_message_to_str()
function defined in osipparser2/osip_message_to_str.c, resulting in a
remote DoS.

CVE-2016-10326 In libosip2 in GNU oSIP 4.1.0, a malformed SIP message
can lead to a heap buffer overflow in the osip_body_to_str() function
defined in osipparser2/osip_body.c, resulting in a remote DoS.

CVE-2017-7853 In libosip2 in GNU oSIP 5.0.0, a malformed SIP message
can lead to a heap buffer overflow in the msg_osip_body_parse()
function defined in osipparser2/osip_message_parse.c, resulting in a
remote DoS.

For Debian 7 'Wheezy', these problems have been fixed in version
3.6.0-4+deb7u1.

We recommend that you upgrade your libosip2 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libosip2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected libosip2-7, and libosip2-dev packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libosip2-7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libosip2-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libosip2-7", reference:"3.6.0-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libosip2-dev", reference:"3.6.0-4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
