#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-466-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91051);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-8869");
  script_osvdb_id(137809);

  script_name(english:"Debian DLA-466-1 : ocaml security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"OCaml versions 4.02.3 and earlier have a runtime bug that, on 64-bit
platforms, causes sizes arguments to an internal memmove call to be
sign-extended from 32 to 64-bits before being passed to the memmove
function. This leads arguments between 2GiB and 4GiB to be interpreted
as larger than they are (specifically, a bit below 2^64), causing a
buffer overflow. Arguments between 4GiB and 6GiB are interpreted as
4GiB smaller than they should be, causing a possible information
leak.A

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ocaml"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:camlp4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:camlp4-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ocaml-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ocaml-base-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ocaml-compiler-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ocaml-interp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ocaml-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ocaml-native-compilers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ocaml-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ocaml-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"camlp4", reference:"3.12.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"camlp4-extra", reference:"3.12.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ocaml", reference:"3.12.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ocaml-base", reference:"3.12.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ocaml-base-nox", reference:"3.12.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ocaml-compiler-libs", reference:"3.12.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ocaml-interp", reference:"3.12.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ocaml-mode", reference:"3.12.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ocaml-native-compilers", reference:"3.12.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ocaml-nox", reference:"3.12.1-4+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"ocaml-source", reference:"3.12.1-4+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
