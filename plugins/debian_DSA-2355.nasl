#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2355. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56986);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/08/10 14:35:56 $");

  script_cve_id("CVE-2011-4357");
  script_osvdb_id(77419);
  script_xref(name:"DSA", value:"2355");

  script_name(english:"Debian DSA-2355-1 : clearsilver - format string vulnerability");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Leo Iannacone and Colin Watson discovered a format string
vulnerability in the Python bindings for the Clearsilver HTML template
system, which may lead to denial of service or the execution of
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/clearsilver"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2355"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the clearsilver packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.10.4-1.3+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 0.10.5-1+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clearsilver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"clearsilver", reference:"0.10.4-1.3+lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"clearsilver-dev", reference:"0.10.5-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libclearsilver-perl", reference:"0.10.5-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"python-clearsilver", reference:"0.10.5-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
