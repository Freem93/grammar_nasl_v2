#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2594. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63357);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-3221");
  script_bugtraq_id(56045);
  script_osvdb_id(86384);
  script_xref(name:"DSA", value:"2594");

  script_name(english:"Debian DSA-2594-1 : virtualbox-ose - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"'halfdog' discovered that incorrect interrupt handling in VirtualBox,
a x86 virtualization solution, can lead to denial of service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/virtualbox-ose"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2594"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the virtualbox-ose packages.

For the stable distribution (squeeze), this problem has been fixed in
version 3.2.10-dfsg-1+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:virtualbox-ose");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/31");
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
if (deb_check(release:"6.0", prefix:"virtualbox-ose", reference:"3.2.10-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-dbg", reference:"3.2.10-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-dkms", reference:"3.2.10-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-fuse", reference:"3.2.10-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-dkms", reference:"3.2.10-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-source", reference:"3.2.10-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-utils", reference:"3.2.10-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-guest-x11", reference:"3.2.10-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-qt", reference:"3.2.10-dfsg-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"virtualbox-ose-source", reference:"3.2.10-dfsg-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
