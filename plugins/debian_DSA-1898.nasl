#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1898. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44763);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:49:56 $");

  script_cve_id("CVE-2009-2185");
  script_bugtraq_id(35452);
  script_xref(name:"DSA", value:"1898");

  script_name(english:"Debian DSA-1898-1 : openswan - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the pluto daemon in openswan, an implementation
of IPSEC and IKE, could crash when processing a crafted X.509
certificate."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1898"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openswan package.

For the old stable distribution (etch), this problem has been fixed in
version 2.4.6+dfsg.2-1.1+etch2.

For the stable distribution (lenny), this problem has been fixed in
version 2.4.12+dfsg-1.3+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
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
if (deb_check(release:"4.0", prefix:"linux-patch-openswan", reference:"2.4.6+dfsg.2-1.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openswan", reference:"2.4.6+dfsg.2-1.1+etch2")) flag++;
if (deb_check(release:"4.0", prefix:"openswan-modules-source", reference:"2.4.6+dfsg.2-1.1+etch2")) flag++;
if (deb_check(release:"5.0", prefix:"linux-patch-openswan", reference:"2.4.12+dfsg-1.3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"openswan", reference:"2.4.12+dfsg-1.3+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"openswan-modules-source", reference:"2.4.12+dfsg-1.3+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
