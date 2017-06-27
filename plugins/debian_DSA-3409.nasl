#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3409. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87163);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_cve_id("CVE-2015-5309");
  script_osvdb_id(129963);
  script_xref(name:"DSA", value:"3409");

  script_name(english:"Debian DSA-3409-1 : putty - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A memory-corrupting integer overflow in the handling of the ECH (erase
characters) control sequence was discovered in PuTTY's terminal
emulator. A remote attacker can take advantage of this flaw to mount a
denial of service or potentially to execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/putty"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/putty"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3409"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the putty packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 0.62-9+deb7u3.

For the stable distribution (jessie), this problem has been fixed in
version 0.63-10+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/02");
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
if (deb_check(release:"7.0", prefix:"pterm", reference:"0.62-9+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"putty", reference:"0.62-9+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"putty-doc", reference:"0.62-9+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"putty-tools", reference:"0.62-9+deb7u3")) flag++;
if (deb_check(release:"8.0", prefix:"pterm", reference:"0.63-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"putty", reference:"0.63-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"putty-doc", reference:"0.63-10+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"putty-tools", reference:"0.63-10+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
