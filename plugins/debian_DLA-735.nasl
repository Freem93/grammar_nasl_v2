#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-735-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95634);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/23 15:32:04 $");

  script_cve_id("CVE-2016-9811");
  script_osvdb_id(147997);

  script_name(english:"Debian DLA-735-1 : gst-plugins-base0.10 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An out of bounds heap read issue was found in gst-plugins-base0.10.

For Debian 7 'Wheezy', these problems have been fixed in version
0.10.36-1.1+deb7u1.

We recommend that you upgrade your gst-plugins-base0.10 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/gst-plugins-base0.10"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-gst-plugins-base-0.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer0.10-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer0.10-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer0.10-plugins-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer0.10-plugins-base-apps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer0.10-plugins-base-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer0.10-plugins-base-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gstreamer0.10-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-base0.10-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgstreamer-plugins-base0.10-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"gir1.2-gst-plugins-base-0.10", reference:"0.10.36-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gstreamer0.10-alsa", reference:"0.10.36-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gstreamer0.10-gnomevfs", reference:"0.10.36-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gstreamer0.10-plugins-base", reference:"0.10.36-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gstreamer0.10-plugins-base-apps", reference:"0.10.36-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gstreamer0.10-plugins-base-dbg", reference:"0.10.36-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gstreamer0.10-plugins-base-doc", reference:"0.10.36-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"gstreamer0.10-x", reference:"0.10.36-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgstreamer-plugins-base0.10-0", reference:"0.10.36-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgstreamer-plugins-base0.10-dev", reference:"0.10.36-1.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
