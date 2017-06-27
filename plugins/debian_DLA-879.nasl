#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-879-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99045);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/31 21:35:24 $");

  script_cve_id("CVE-2017-6369");
  script_osvdb_id(154295);
  script_xref(name:"IAVB", value:"2017-B-0039");

  script_name(english:"Debian DLA-879-1 : firebird2.5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"George Noseevich discovered that firebird2.5, a relational database
system, did not properly check User-Defined Functions (UDF), thus
allowing remote authenticated users to execute arbitrary code on the
firebird server.

For Debian 7 'Wheezy', these problems have been fixed in version
2.5.2.26540.ds4-1~deb7u3.

We recommend that you upgrade your firebird2.5 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00038.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/firebird2.5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-classic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-classic-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-classic-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-common-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-super");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-super-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:firebird2.5-superclassic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfbclient2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfbclient2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfbembed2.5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libib-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
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
if (deb_check(release:"7.0", prefix:"firebird-dev", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-classic", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-classic-common", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-classic-dbg", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-common", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-common-doc", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-doc", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-examples", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-server-common", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-super", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-super-dbg", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"firebird2.5-superclassic", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libfbclient2", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libfbclient2-dbg", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libfbembed2.5", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libib-util", reference:"2.5.2.26540.ds4-1~deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
