#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1851. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44716);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2009-1438");
  script_bugtraq_id(30801);
  script_osvdb_id(53801);
  script_xref(name:"DSA", value:"1851");

  script_name(english:"Debian DSA-1851-1 : gst-plugins-bad0.10 - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that gst-plugins-bad0.10, the GStreamer plugins from
the 'bad' set, is prone to an integer overflow when processing a MED
file with a crafted song comment or song name."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=527075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1851"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gst-plugins-bad0.10 packages.

For the oldstable distribution (etch), this problem has been fixed in
version 0.10.3-3.1+etch3.

For the stable distribution (lenny), this problem has been fixed in
version 0.10.7-2+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gst-plugins-bad0.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"gstreamer0.10-plugins-bad", reference:"0.10.3-3.1+etch3")) flag++;
if (deb_check(release:"5.0", prefix:"gstreamer0.10-plugins-bad", reference:"0.10.7-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"gstreamer0.10-plugins-bad-dbg", reference:"0.10.7-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"gstreamer0.10-plugins-bad-doc", reference:"0.10.7-2+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"gstreamer0.10-sdl", reference:"0.10.7-2+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
