#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2374. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57514);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-4073");
  script_bugtraq_id(50440);
  script_osvdb_id(76725);
  script_xref(name:"DSA", value:"2374");

  script_name(english:"Debian DSA-2374-1 : openswan - implementation error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The information security group at ETH Zurich discovered a denial of
service vulnerability in the crypto helper handler of the IKE daemon
pluto. More information can be found in the upstream advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=650674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://openswan.org/download/CVE-2011-4073/CVE-2011-4073.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openswan"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2374"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openswan packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:2.4.12+dfsg-1.3+lenny4.

For the stable distribution (squeeze), this problem has been fixed in
version 1:2.6.28+dfsg-5+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"openswan", reference:"1:2.4.12+dfsg-1.3+lenny4")) flag++;
if (deb_check(release:"6.0", prefix:"openswan", reference:"1:2.6.28+dfsg-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openswan-dbg", reference:"1:2.6.28+dfsg-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openswan-doc", reference:"1:2.6.28+dfsg-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openswan-modules-dkms", reference:"1:2.6.28+dfsg-5+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"openswan-modules-source", reference:"1:2.6.28+dfsg-5+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
