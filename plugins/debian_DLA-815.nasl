#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-815-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96963);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/04/05 13:27:12 $");

  script_cve_id("CVE-2017-0358");
  script_osvdb_id(151244);

  script_name(english:"Debian DLA-815-1 : ntfs-3g security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jann Horn of Google Project Zero discovered that NTFS-3G, a read-write
NTFS driver for FUSE, does not scrub the environment before executing
modprobe with elevated privileges. A local user can take advantage of
this flaw for local root privilege escalation.

For Debian 7 'Wheezy', these problems have been fixed in version
1:2012.1.15AR.5-2.1+deb7u3.

We recommend that you upgrade your ntfs-3g packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ntfs-3g"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Debian/Ubuntu ntfs-3g Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfs-3g");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfs-3g-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfs-3g-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ntfsprogs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/03");
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
if (deb_check(release:"7.0", prefix:"ntfs-3g", reference:"1:2012.1.15AR.5-2.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ntfs-3g-dbg", reference:"1:2012.1.15AR.5-2.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ntfs-3g-dev", reference:"1:2012.1.15AR.5-2.1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"ntfsprogs", reference:"1:2012.1.15AR.5-2.1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
