#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3336. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85466);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/08/18 14:49:03 $");

  script_cve_id("CVE-2015-2721", "CVE-2015-2730");
  script_osvdb_id(124092, 124105);
  script_xref(name:"DSA", value:"3336");

  script_name(english:"Debian DSA-3336-1 : nss - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in nss, the Mozilla
Network Security Service library. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2015-2721
    Karthikeyan Bhargavan discovered that NSS incorrectly
    handles state transitions for the TLS state machine. A
    man-in-the-middle attacker could exploit this flaw to
    skip the ServerKeyExchange message and remove the
    forward-secrecy property.

  - CVE-2015-2730
    Watson Ladd discovered that NSS does not properly
    perform Elliptical Curve Cryptography (ECC)
    multiplication, allowing a remote attacker to
    potentially spoof ECDSA signatures."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nss"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/nss"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3336"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nss packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 2:3.14.5-1+deb7u5.

For the stable distribution (jessie), these problems have been fixed
in version 2:3.17.2-1.1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libnss3", reference:"2:3.14.5-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-1d", reference:"2:3.14.5-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-dbg", reference:"2:3.14.5-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-dev", reference:"2:3.14.5-1+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-tools", reference:"2:3.14.5-1+deb7u5")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3", reference:"2:3.17.2-1.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-1d", reference:"2:3.17.2-1.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-dbg", reference:"2:3.17.2-1.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-dev", reference:"2:3.17.2-1.1+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-tools", reference:"2:3.17.2-1.1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
