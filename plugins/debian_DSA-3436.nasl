#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3436. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87827);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-7575");
  script_osvdb_id(132305);
  script_xref(name:"DSA", value:"3436");

  script_name(english:"Debian DSA-3436-1 : openssl - security update (SLOTH)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Karthikeyan Bhargavan and Gaetan Leurent at INRIA discovered a flaw in
the TLS 1.2 protocol which could allow the MD5 hash function to be
used for signing ServerKeyExchange and Client Authentication packets
during a TLS handshake. A man-in-the-middle attacker could exploit
this flaw to conduct collision attacks to impersonate a TLS server or
an authenticated TLS client.

More information can be found at
https://www.mitls.org/pages/attacks/SLOTH"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mitls.org/pages/attacks/SLOTH"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3436"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 1.0.1e-2+deb7u19.

For the stable distribution (jessie), the testing distribution
(stretch) and the unstable distribution (sid), this issue was already
addressed in version 1.0.1f-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/08");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libssl-dev", reference:"1.0.1e-2+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"libssl-doc", reference:"1.0.1e-2+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0", reference:"1.0.1e-2+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"libssl1.0.0-dbg", reference:"1.0.1e-2+deb7u19")) flag++;
if (deb_check(release:"7.0", prefix:"openssl", reference:"1.0.1e-2+deb7u19")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
