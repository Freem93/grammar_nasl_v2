#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3184. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81794);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/19 17:45:44 $");

  script_cve_id("CVE-2014-3591", "CVE-2015-0837", "CVE-2015-1606");
  script_osvdb_id(118468, 118978, 118979);
  script_xref(name:"DSA", value:"3184");

  script_name(english:"Debian DSA-3184-1 : gnupg - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in GnuPG, the GNU Privacy
Guard :

  - CVE-2014-3591
    The Elgamal decryption routine was susceptible to a
    side-channel attack discovered by researchers of Tel
    Aviv University. Ciphertext blinding was enabled to
    counteract it. Note that this may have a quite
    noticeable impact on Elgamal decryption performance.

  - CVE-2015-0837
    The modular exponentiation routine mpi_powm() was
    susceptible to a side-channel attack caused by
    data-dependent timing variations when accessing its
    internal pre-computed table.

  - CVE-2015-1606
    The keyring parsing code did not properly reject certain
    packet types not belonging in a keyring, which caused an
    access to memory already freed. This could allow remote
    attackers to cause a denial of service (crash) via
    crafted keyring files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=778652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3591"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gnupg"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3184"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gnupg packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.4.12-7+deb7u7.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 1.4.18-7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"gnupg", reference:"1.4.12-7+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg-curl", reference:"1.4.12-7+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"gnupg-udeb", reference:"1.4.12-7+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv", reference:"1.4.12-7+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv-udeb", reference:"1.4.12-7+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"gpgv-win32", reference:"1.4.12-7+deb7u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
