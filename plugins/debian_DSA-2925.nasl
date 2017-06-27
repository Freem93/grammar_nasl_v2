#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2925. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73924);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2014-3121");
  script_bugtraq_id(67155);
  script_osvdb_id(106475);
  script_xref(name:"DSA", value:"2925");

  script_name(english:"Debian DSA-2925-1 : rxvt-unicode - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Phillip Hallam-Baker discovered that window property values could be
queried in rxvt-unicode, resulting in the potential execution of
arbitrary commands."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=746593"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/rxvt-unicode"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/rxvt-unicode"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2925"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the rxvt-unicode packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 9.07-2+deb6u1.

For the stable distribution (wheezy), this problem has been fixed in
version 9.15-2+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rxvt-unicode");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"rxvt-unicode", reference:"9.07-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"rxvt-unicode-lite", reference:"9.07-2+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"rxvt-unicode-ml", reference:"9.07-2+deb6u1")) flag++;
if (deb_check(release:"7.0", prefix:"rxvt-unicode", reference:"9.15-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"rxvt-unicode-256color", reference:"9.15-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"rxvt-unicode-lite", reference:"9.15-2+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"rxvt-unicode-ml", reference:"9.15-2+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
