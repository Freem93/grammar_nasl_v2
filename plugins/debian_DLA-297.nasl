#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-297-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85585);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:17 $");

  script_cve_id("CVE-2015-5069", "CVE-2015-5070");
  script_bugtraq_id(75424, 75425);
  script_osvdb_id(123716);

  script_name(english:"Debian DLA-297-1 : wesnoth-1.8 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Wesnoth implements a text preprocessing language that is used in
conjunction with its own game scripting language. It also has a
built-in Lua interpreter and API. Both the Lua API and the
preprocessor make use of the same function
(filesystem::get_wml_location()) to resolve file paths so that only
content from the user's data directory can be read.

However, the function did not explicitly disallow files with
the .pbl extension. The contents of these files could thus
be stored in saved game files or even transmitted directly
to other users in a networked game. Among the information
that's compromised is a user-defined passphrase used to
authenticate uploads to the game's content server.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/08/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/wesnoth-1.8"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-aoi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-did");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-dm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-ei");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-httt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-l");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-low");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-music");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-sof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-sotbe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-thot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-trow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-tsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-ttb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-1.8-utbs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-editor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wesnoth-music");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/24");
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
if (deb_check(release:"6.0", prefix:"wesnoth", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-aoi", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-core", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-data", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-dbg", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-did", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-dm", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-ei", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-httt", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-l", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-low", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-music", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-nr", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-server", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-sof", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-sotbe", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-thot", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-tools", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-trow", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-tsg", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-ttb", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-1.8-utbs", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-all", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-core", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-editor", reference:"1:1.8.5-1+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"wesnoth-music", reference:"1:1.8.5-1+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
