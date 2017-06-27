#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2459. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58883);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-0249", "CVE-2012-0250", "CVE-2012-0255");
  script_bugtraq_id(52531);
  script_xref(name:"DSA", value:"2459");

  script_name(english:"Debian DSA-2459-2 : quagga - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Quagga, a routing
daemon.

  - CVE-2012-0249
    A buffer overflow in the ospf_ls_upd_list_lsa function
    in the OSPFv2 implementation allows remote attackers to
    cause a denial of service (assertion failure and daemon
    exit) via a Link State Update (aka LS Update) packet
    that is smaller than the length specified in its header.

  - CVE-2012-0250
    A buffer overflow in the OSPFv2 implementation allows
    remote attackers to cause a denial of service (daemon
    crash) via a Link State Update (aka LS Update) packet
    containing a network-LSA link-state advertisement for
    which the data-structure length is smaller than the
    value in the Length header field.

  - CVE-2012-0255
    The BGP implementation does not properly use message
    buffers for OPEN messages, which allows remote attackers
    impersonating a configured BGP peer to cause a denial of
    service (assertion failure and daemon exit) via a
    message associated with a malformed AS4 capability.

This security update upgrades the quagga package to the most recent
upstream release. This release includes other corrections, such as
hardening against unknown BGP path attributes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0250"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0255"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/quagga"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2459"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the quagga packages.

For the stable distribution (squeeze), these problems have been fixed
in version 0.99.20.1-0+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:quagga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/27");
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
if (deb_check(release:"6.0", prefix:"quagga", reference:"0.99.20.1-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"quagga-dbg", reference:"0.99.20.1-0+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"quagga-doc", reference:"0.99.20.1-0+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
