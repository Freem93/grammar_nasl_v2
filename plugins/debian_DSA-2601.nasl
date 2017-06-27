#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2601. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63386);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-6085");
  script_bugtraq_id(57102);
  script_xref(name:"DSA", value:"2601");

  script_name(english:"Debian DSA-2601-1 : gnupg, gnupg2 - missing input sanitation");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"KB Sriram discovered that GnuPG, the GNU Privacy Guard did not
sufficiently sanitise public keys on import, which could lead to
memory and keyring corruption.

The problem affects both version 1, in the 'gnupg' package, and
version two, in the 'gnupg2' package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=697108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=697251"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/gnupg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/gnupg2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2601"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnupg and/or gnupg2 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.10-4+squeeze1 of gnupg and version 2.0.14-2+squeeze1 of
gnupg2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"gnupg", reference:"1.4.10-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnupg-agent", reference:"1.4.10-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnupg-curl", reference:"1.4.10-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnupg-udeb", reference:"1.4.10-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gnupg2", reference:"1.4.10-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gpgsm", reference:"1.4.10-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gpgv", reference:"1.4.10-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"gpgv-udeb", reference:"1.4.10-4+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
