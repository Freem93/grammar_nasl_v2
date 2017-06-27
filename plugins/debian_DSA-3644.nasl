#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3644. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92795);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-5384");
  script_osvdb_id(142659);
  script_xref(name:"DSA", value:"3644");

  script_name(english:"Debian DSA-3644-1 : fontconfig - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tobias Stoeckmann discovered that cache files are insufficiently
validated in fontconfig, a generic font configuration library. An
attacker can trigger arbitrary free() calls, which in turn allows
double free attacks and therefore arbitrary code execution. In
combination with setuid binaries using crafted cache files, this could
allow privilege escalation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=833570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/fontconfig"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3644"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the fontconfig packages.

For the stable distribution (jessie), this problem has been fixed in
version 2.11.0-6.3+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fontconfig");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/09");
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
if (deb_check(release:"8.0", prefix:"fontconfig", reference:"2.11.0-6.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"fontconfig-config", reference:"2.11.0-6.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfontconfig1", reference:"2.11.0-6.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfontconfig1-dbg", reference:"2.11.0-6.3+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libfontconfig1-dev", reference:"2.11.0-6.3+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
