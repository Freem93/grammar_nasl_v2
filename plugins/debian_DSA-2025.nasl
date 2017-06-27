#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2025. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45397);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2463", "CVE-2009-3072", "CVE-2009-3075", "CVE-2010-0163");
  script_bugtraq_id(35769, 35888, 35891, 36343, 38831);
  script_xref(name:"DSA", value:"2025");

  script_name(english:"Debian DSA-2025-1 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Icedove
mail client, an unbranded version of the Thunderbird mail client. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2009-2408
    Dan Kaminsky and Moxie Marlinspike discovered that
    icedove does not properly handle a '\0' character in a
    domain name in the subject's Common Name (CN) field of
    an X.509 certificate (MFSA 2009-42).

  - CVE-2009-2404
    Moxie Marlinspike reported a heap overflow vulnerability
    in the code that handles regular expressions in
    certificate names (MFSA 2009-43).

  - CVE-2009-2463
    monarch2020 discovered an integer overflow in a base64
    decoding function (MFSA 2010-07).

  - CVE-2009-3072
    Josh Soref discovered a crash in the BinHex decoder
    (MFSA 2010-07).

  - CVE-2009-3075
    Carsten Book reported a crash in the JavaScript engine
    (MFSA 2010-07).

  - CVE-2010-0163
    Ludovic Hirlimann reported a crash indexing some
    messages with attachments, which could lead to the
    execution of arbitrary code (MFSA 2010-07)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2463"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0163"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2025"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (lenny), these problems have been fixed in
version 2.0.0.24-0lenny1.

Due to a problem with the archive system it is not possible to release
all architectures. The missing architectures will be installed into
the archive once they become available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"icedove", reference:"2.0.0.24-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"icedove-dbg", reference:"2.0.0.24-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"icedove-dev", reference:"2.0.0.24-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"icedove-gnome-support", reference:"2.0.0.24-0lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
