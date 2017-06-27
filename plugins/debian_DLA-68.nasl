#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-68-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82213);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/23 15:32:04 $");

  script_cve_id("CVE-2014-3875", "CVE-2014-3876", "CVE-2014-3877");
  script_bugtraq_id(67783, 67785, 67788);
  script_osvdb_id(107659);

  script_name(english:"Debian DLA-68-1 : fex security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"[CVE-2014-3875]

When inserting encoded newline characters into a request to rup,
additional HTTP headers can be injected into the reply, as well as new
HTML code on the top of the website.

[CVE-2014-3876] The parameter akey is reflected unfiltered as part of
the HTML page. Some characters are forbidden in the GET parameter due
to filtering of the URL, but this can be circumvented by using a POST
parameter. Nevertheless, this issue is exploitable via the GET
parameter alone, with some user interaction.

[CVE-2014-3877] The parameter addto is reflected only slightly
filtered back to the user as part of the HTML page. Some characters
are forbidden in the GET parameter due to filtering of the URL, but
this can be circumvented by using a POST parameter. Nevertheless, this
issue is exploitable via the GET parameter alone, with some user
interaction.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/09/msg00025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/fex"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected fex, and fex-utils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fex-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"fex", reference:"20100208+debian1-1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"fex-utils", reference:"20100208+debian1-1+squeeze4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
