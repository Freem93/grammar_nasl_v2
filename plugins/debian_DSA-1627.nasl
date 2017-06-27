#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1627. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33826);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2008-2235");
  script_xref(name:"DSA", value:"1627");

  script_name(english:"Debian DSA-1627-2 : opensc - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Chaskiel M Grundman discovered that opensc, a library and utilities to
handle smart cards, would initialise smart cards with the Siemens
CardOS M4 card operating system without proper access rights. This
allowed everyone to change the card's PIN.

With this bug anyone can change a user PIN without having the PIN or
PUK or the superusers PIN or PUK. However it can not be used to figure
out the PIN. If the PIN on your card is still the same you always had,
there's a reasonable chance that this vulnerability has not been
exploited.

This vulnerability affects only smart cards and USB crypto tokens
based on Siemens CardOS M4, and within that group only those that were
initialised with OpenSC. Users of other smart cards and USB crypto
tokens, or cards that have been initialised with some software other
than OpenSC, are not affected.

After upgrading the package, runningpkcs15-tool -Twill show you
whether the card is fine or vulnerable. If the card is vulnerable, you
need to update the security setting using:pkcs15-tool -T -U."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1627"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the opensc package and check the card(s) with the command
described above.

For the stable distribution (etch), this problem has been fixed in
version 0.11.1-2etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:N");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libopensc2", reference:"0.11.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libopensc2-dbg", reference:"0.11.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libopensc2-dev", reference:"0.11.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-opensc", reference:"0.11.1-2etch2")) flag++;
if (deb_check(release:"4.0", prefix:"opensc", reference:"0.11.1-2etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
