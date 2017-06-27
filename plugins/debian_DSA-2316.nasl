#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2316. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56394);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-3323", "CVE-2011-3324", "CVE-2011-3325", "CVE-2011-3326", "CVE-2011-3327");
  script_bugtraq_id(49784);
  script_osvdb_id(75728, 75729, 75730, 75731, 75732);
  script_xref(name:"DSA", value:"2316");

  script_name(english:"Debian DSA-2316-1 : quagga - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Riku Hietamaki, Tuomo Untinen and Jukka Taimisto discovered several
vulnerabilities in Quagga, an Internet routing daemon :

  - CVE-2011-3323
    A stack-based buffer overflow while decoding Link State
    Update packets with a malformed Inter Area Prefix LSA
    can cause the ospf6d process to crash or (potentially)
    execute arbitrary code.

  - CVE-2011-3324
    The ospf6d process can crash while processing a Database
    Description packet with a crafted
    Link-State-Advertisement.

  - CVE-2011-3325
    The ospfd process can crash while processing a crafted
    Hello packet.

  - CVE-2011-3326
    The ospfd process crashes while processing
    Link-State-Advertisements of a type not known to Quagga.

  - CVE-2011-3327
    A heap-based buffer overflow while processing BGP UPDATE
    messages containing an Extended Communities path
    attribute can cause the bgpd process to crash or
    (potentially) execute arbitrary code.

The OSPF-related vulnerabilities require that potential attackers send
packets to a vulnerable Quagga router; the packets are not distributed
over OSPF. In contrast, the BGP UPDATE messages could be propagated by
some routers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3324"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3325"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3327"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/quagga"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2316"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the quagga packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 0.99.10-1lenny6.

For the stable distribution (squeeze), these problems have been fixed
in version 0.99.17-2+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"quagga", reference:"0.99.10-1lenny6")) flag++;
if (deb_check(release:"6.0", prefix:"quagga", reference:"0.99.17-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"quagga-dbg", reference:"0.99.17-2+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"quagga-doc", reference:"0.99.17-2+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
