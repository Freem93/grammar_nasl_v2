#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-819. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19788);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-2491");
  script_bugtraq_id(14620);
  script_xref(name:"DSA", value:"819");

  script_name(english:"Debian DSA-819-1 : python2.1 - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An integer overflow with a subsequent buffer overflow has been
detected in PCRE, the Perl Compatible Regular Expressions library,
which allows an attacker to execute arbitrary code, and is also
present in Python. Exploiting this vulnerability requires an attacker
to specify the used regular expression."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=324531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-819"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python2.1 packages.

For the old stable distribution (woody) this problem has been fixed in
version 2.1.3-3.4.

For the stable distribution (sarge) this problem has been fixed in
version 2.1.3dfsg-1sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"idle", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"idle-python2.1", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python-dev", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python-doc", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python-elisp", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python-examples", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python-gdbm", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python-mpz", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python-tk", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python-xmlbase", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-dev", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-doc", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-elisp", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-examples", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-gdbm", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-mpz", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-tk", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.0", prefix:"python2.1-xmlbase", reference:"2.1.3-3.4")) flag++;
if (deb_check(release:"3.1", prefix:"idle-python2.1", reference:"2.1.3dfsg-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1", reference:"2.1.3dfsg-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1-dev", reference:"2.1.3dfsg-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1-doc", reference:"2.1.3dfsg-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1-examples", reference:"2.1.3dfsg-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1-gdbm", reference:"2.1.3dfsg-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1-mpz", reference:"2.1.3dfsg-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1-tk", reference:"2.1.3dfsg-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"python2.1-xmlbase", reference:"2.1.3dfsg-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
