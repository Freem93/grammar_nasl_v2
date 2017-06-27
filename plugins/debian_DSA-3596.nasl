#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3596. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91490);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/12/06 20:25:09 $");

  script_cve_id("CVE-2016-0749", "CVE-2016-2150");
  script_osvdb_id(139486, 139487);
  script_xref(name:"DSA", value:"3596");

  script_name(english:"Debian DSA-3596-1 : spice - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in spice, a SPICE protocol
client and server library. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2016-0749
    Jing Zhao of Red Hat discovered a memory allocation
    flaw, leading to a heap-based buffer overflow in spice's
    smartcard interaction. A user connecting to a guest VM
    via spice can take advantage of this flaw to cause a
    denial-of-service (QEMU process crash), or potentially
    to execute arbitrary code on the host with the
    privileges of the hosting QEMU process.

  - CVE-2016-2150
    Frediano Ziglio of Red Hat discovered that a malicious
    guest inside a virtual machine can take control of the
    corresponding QEMU process in the host using crafted
    primary surface parameters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-0749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/spice"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3596"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the spice packages.

For the stable distribution (jessie), these problems have been fixed
in version 0.12.5-1+deb8u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/07");
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
if (deb_check(release:"8.0", prefix:"libspice-server-dev", reference:"0.12.5-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-server1", reference:"0.12.5-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-server1-dbg", reference:"0.12.5-1+deb8u3")) flag++;
if (deb_check(release:"8.0", prefix:"spice-client", reference:"0.12.5-1+deb8u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
