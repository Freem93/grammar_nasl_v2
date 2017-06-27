#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3790. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97217);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2016-9577", "CVE-2016-9578");
  script_osvdb_id(151470, 151473);
  script_xref(name:"DSA", value:"3790");

  script_name(english:"Debian DSA-3790-1 : spice - security update");
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

  - CVE-2016-9577
    Frediano Ziglio of Red Hat discovered a buffer overflow
    vulnerability in the main_channel_alloc_msg_rcv_buf
    function. An authenticated attacker can take advantage
    of this flaw to cause a denial of service (spice server
    crash), or possibly, execute arbitrary code.

  - CVE-2016-9578
    Frediano Ziglio of Red Hat discovered that spice does
    not properly validate incoming messages. An attacker
    able to connect to the spice server could send crafted
    messages which would cause the process to crash."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=854336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9577"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-9578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/spice"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3790"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the spice packages.

For the stable distribution (jessie), these problems have been fixed
in version 0.12.5-1+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:spice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"libspice-server-dev", reference:"0.12.5-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-server1", reference:"0.12.5-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libspice-server1-dbg", reference:"0.12.5-1+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"spice-client", reference:"0.12.5-1+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
