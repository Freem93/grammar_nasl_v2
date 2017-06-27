#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1839. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44704);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/01 20:56:51 $");

  script_cve_id("CVE-2009-1932");
  script_osvdb_id(54827);
  script_xref(name:"DSA", value:"1839");

  script_name(english:"Debian DSA-1839-1 : gst-plugins-good0.10 - integer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It has been discovered that gst-plugins-good0.10, the GStreamer
plugins from the 'good' set, are prone to an integer overflow, when
processing a large PNG file. This could lead to the execution of
arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=531631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=532352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1839"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the gst-plugins-good0.10 packages.

For the stable distribution (lenny), this problem has been fixed in
version 0.10.8-4.1~lenny2.

For the oldstable distribution (etch), this problem has been fixed in
version 0.10.4-4+etch1.

Packages for the s390 and hppa architectures will be released once
they are available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gst-plugins-good0.10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"gstreamer0.10-esd", reference:"0.10.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gstreamer0.10-plugins-good", reference:"0.10.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gstreamer0.10-plugins-good-dbg", reference:"0.10.4-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gstreamer0.10-plugins-good-doc", reference:"0.10.4-4+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"gstreamer0.10-esd", reference:"0.10.8-4.1~lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"gstreamer0.10-plugins-good", reference:"0.10.8-4.1~lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"gstreamer0.10-plugins-good-dbg", reference:"0.10.8-4.1~lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"gstreamer0.10-plugins-good-doc", reference:"0.10.8-4.1~lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
