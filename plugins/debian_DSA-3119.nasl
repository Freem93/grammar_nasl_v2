#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3119. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80393);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/08/27 13:25:26 $");

  script_cve_id("CVE-2014-6272", "CVE-2015-6525");
  script_osvdb_id(113157);
  script_xref(name:"DSA", value:"3119");

  script_name(english:"Debian DSA-3119-1 : libevent - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andrew Bartlett of Catalyst reported a defect affecting certain
applications using the Libevent evbuffer API. This defect leaves
applications which pass insanely large inputs to evbuffers open to a
possible heap overflow or infinite loop. In order to exploit this
flaw, an attacker needs to be able to find a way to provoke the
program into trying to make a buffer chunk larger than what will fit
into a single size_t or off_t."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=774645"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libevent"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3119"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libevent packages.

For the stable distribution (wheezy), this problem has been fixed in
version 2.0.19-stable-3+deb7u1.

For the upcoming stable distribution (jessie) and the unstable
distribution (sid), this problem will be fixed soon."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libevent");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libevent-2.0-5", reference:"2.0.19-stable-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-core-2.0-5", reference:"2.0.19-stable-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-dbg", reference:"2.0.19-stable-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-dev", reference:"2.0.19-stable-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-extra-2.0-5", reference:"2.0.19-stable-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-openssl-2.0-5", reference:"2.0.19-stable-3+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libevent-pthreads-2.0-5", reference:"2.0.19-stable-3+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
