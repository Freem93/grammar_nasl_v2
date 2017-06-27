#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-853-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97669);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/20 15:44:32 $");

  script_cve_id("CVE-2017-2640");
  script_osvdb_id(153426);
  script_xref(name:"IAVB", value:"2017-B-0029");

  script_name(english:"Debian DLA-853-1 : pidgin security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that an invalid XML file can trigger an out-of-bound
memory access in Pidgin, a multi-protocol instant messaging client,
when it is sent by a malicious server. This might lead to a crash or,
in some extreme cases, to remote code execution in the client-side.

For Debian 7 'Wheezy', these problems have been fixed in version
2.10.10-1~deb7u3.

We recommend that you upgrade your pidgin packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/pidgin"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:finch-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpurple-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpurple-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpurple0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pidgin-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pidgin-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pidgin-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/13");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
if (deb_check(release:"7.0", prefix:"finch", reference:"2.10.10-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"finch-dev", reference:"2.10.10-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libpurple-bin", reference:"2.10.10-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libpurple-dev", reference:"2.10.10-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libpurple0", reference:"2.10.10-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin", reference:"2.10.10-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin-data", reference:"2.10.10-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin-dbg", reference:"2.10.10-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"pidgin-dev", reference:"2.10.10-1~deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
