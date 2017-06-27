#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-228. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15065);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/17 23:58:37 $");

  script_cve_id("CVE-2003-0031", "CVE-2003-0032");
  script_bugtraq_id(6510, 6512);
  script_xref(name:"DSA", value:"228");

  script_name(english:"Debian DSA-228-1 : libmcrypt - buffer overflows and memory leak");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ilia Alshanetsky discovered several buffer overflows in libmcrypt, a
decryption and encryption library, that originates from improper or
lacking input validation. By passing input which is longer than
expected to a number of functions (multiple functions are affected)
the user can successfully make libmcrypt crash and may be able to
insert arbitrary, malicious code which will be executed under the user
libmcrypt runs as, e.g. inside a web server.

Another vulnerability exists in the way libmcrypt loads algorithms via
libtool. When different algorithms are loaded dynamically, each time
an algorithm is loaded a small part of memory is leaked. In a
persistent environment (web server) this could lead to a memory
exhaustion attack that will exhaust all available memory by launching
repeated requests at an application utilizing the mcrypt library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-228"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libmcrypt packages.

For the current stable distribution (woody) these problems have been
fixed in version 2.5.0-1woody1.

The old stable distribution (potato) does not contain libmcrypt
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmcrypt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/14");
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
if (deb_check(release:"3.0", prefix:"libmcrypt-dev", reference:"2.5.0-1woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libmcrypt4", reference:"2.5.0-1woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
