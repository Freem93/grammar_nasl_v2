#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2771. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70355);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/16 15:43:09 $");

  script_cve_id("CVE-2013-4256", "CVE-2013-4258");
  script_bugtraq_id(61843, 61848, 61852);
  script_xref(name:"DSA", value:"2771");

  script_name(english:"Debian DSA-2771-1 : nas - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Hamid Zamani discovered multiple security problems (buffer overflows,
format string vulnerabilities and missing input sanitising), which
could lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/nas"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nas"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2771"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nas packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.9.2-4squeeze1.

For the stable distribution (wheezy), these problems have been fixed
in version 1.9.3-5wheezy1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nas");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/10");
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
if (deb_check(release:"6.0", prefix:"libaudio-dev", reference:"1.9.2-4squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libaudio2", reference:"1.9.2-4squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"nas", reference:"1.9.2-4squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"nas-bin", reference:"1.9.2-4squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"nas-doc", reference:"1.9.2-4squeeze1")) flag++;
if (deb_check(release:"7.0", prefix:"libaudio-dev", reference:"1.9.3-5wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"libaudio2", reference:"1.9.3-5wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"nas", reference:"1.9.3-5wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"nas-bin", reference:"1.9.3-5wheezy1")) flag++;
if (deb_check(release:"7.0", prefix:"nas-doc", reference:"1.9.3-5wheezy1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
