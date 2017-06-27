#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2626. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64662);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2009-3555", "CVE-2012-4929");
  script_bugtraq_id(36935, 55704);
  script_osvdb_id(85927);
  script_xref(name:"DSA", value:"2626");

  script_name(english:"Debian DSA-2626-1 : lighttpd - several issues");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the TLS/SSL protocol. This
update addresses these protocol vulnerabilities in lighttpd.

  - CVE-2009-3555
    Marsh Ray, Steve Dispensa, and Martin Rex discovered
    that the TLS and SSLv3 protocols do not properly
    associate renegotiation handshakes with an existing
    connection, which allows man-in-the-middle attackers to
    insert data into HTTPS sessions. This issue is solved in
    lighttpd by disabling client initiated renegotiation by
    default.

       Those users that do actually need such renegotiations, can
       reenable them via the new 'ssl.disable-client-renegotiation'
       parameter.

  - CVE-2012-4929
    Juliano Rizzo and Thai Duong discovered a weakness in
    the TLS/SSL protocol when using compression. This side
    channel attack, dubbed'CRIME', allows eavesdroppers to
    gather information to recover the original plaintext in
    the protocol. This update disables compression."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=700399"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4929"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/lighttpd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2626"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lighttpd packages.

For the stable distribution (squeeze), these problems have been fixed
in version 1.4.28-2+squeeze1.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lighttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/18");
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
if (deb_check(release:"6.0", prefix:"lighttpd", reference:"1.4.28-2+squeeze1.2")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-doc", reference:"1.4.28-2+squeeze1.2")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-cml", reference:"1.4.28-2+squeeze1.2")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-magnet", reference:"1.4.28-2+squeeze1.2")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-mysql-vhost", reference:"1.4.28-2+squeeze1.2")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-trigger-b4-dl", reference:"1.4.28-2+squeeze1.2")) flag++;
if (deb_check(release:"6.0", prefix:"lighttpd-mod-webdav", reference:"1.4.28-2+squeeze1.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
