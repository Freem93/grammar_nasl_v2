#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-680-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94294);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/23 15:32:04 $");

  script_cve_id("CVE-2016-7543");
  script_osvdb_id(144718);

  script_name(english:"Debian DLA-680-2 : bash version number correction");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is a correction of DLA 680-1 that mentioned that bash
4.2+dfsg-0.1+deb7u3 was corrected. The corrected package version was
4.2+dfsg-0.1+deb7u4.

For completeness the text from DLA 680-1 available below with only
corrected version information. No other changes.

An old attack vector has been corrected in bash (a sh-compatible
command language interpreter).

CVE-2016-7543 Specially crafted SHELLOPTS+PS4 environment variables in
combination with insecure setuid binaries.

The setuid binary had to both use setuid() function call in
combination with a system() or popen() function call. With this
combination it is possible to gain root access.

I addition bash have to be the default shell (/bin/sh have to point to
bash) for the system to be vulnerable.

The default shell in Debian is dash and there are no known setuid
binaries in Debian with the, above described, insecure combination.

There could however be local software with the, above described,
insecure combination that could benefit from this correction.

For Debian 7 'Wheezy', this problem have been fixed in version
4.2+dfsg-0.1+deb7u4.

We recommend that you upgrade your bash packages.

If there are local software that have the insecure combination and do
a setuid() to some other user than root, then the update will not
correct that problem. That problem have to be addressed in the
insecure setuid binary.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00045.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/bash"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bash-builtins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bash-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bash-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");
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
if (deb_check(release:"7.0", prefix:"bash", reference:"4.2+dfsg-0.1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"bash-builtins", reference:"4.2+dfsg-0.1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"bash-doc", reference:"4.2+dfsg-0.1+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"bash-static", reference:"4.2+dfsg-0.1+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
