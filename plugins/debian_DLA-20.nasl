#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-20-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82168);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:17 $");

  script_cve_id("CVE-2012-3512", "CVE-2013-6048", "CVE-2013-6359");
  script_bugtraq_id(55698, 64188, 64189);

  script_name(english:"Debian DLA-20-1 : munin security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"[ Christoph Biedl ]

  - munin-node: more secure state file handling, introducing
    a new plugin state directory root, owned by uid 0. Then
    each plugin runs in its own UID plugin state directory,
    owned by that UID. (Closes: #684075), (Closes: #679897),
    closes CVE-2012-3512.

  - plugins: use runtime $ENV{MUNIN_PLUGSTATE}. So all
    properly written plugins will use
    /var/lib/munin-node/plugin-state/$uid/$some_file now -
    please report plugins that are still using
    /var/lib/munin/plugin-state/ - as those might pose a
    security risk!

  - Validate multigraph plugin name, CVE-2013-6048.

  - Don't abort data collection for a node due to malicious
    node, fixing munin#1397, CVE-2013-6359.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/08/msg00004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/munin"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-java-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:munin-plugins-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"munin", reference:"1.4.5-3+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"munin-common", reference:"1.4.5-3+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"munin-java-plugins", reference:"1.4.5-3+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"munin-node", reference:"1.4.5-3+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"munin-plugins-extra", reference:"1.4.5-3+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
