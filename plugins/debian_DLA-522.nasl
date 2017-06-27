#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-522-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91733);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:03:52 $");

  script_cve_id("CVE-2016-0772", "CVE-2016-5636", "CVE-2016-5699");
  script_osvdb_id(115884, 140038, 140125);

  script_name(english:"Debian DLA-522-1 : python2.7 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2016-0772 A vulnerability in smtplib allowing MITM
    attacker to perform a startTLS stripping attack. smtplib
    does not seem to raise an exception when the remote end
    (smtp server) is capable of negotiating starttls but
    fails to respond with 220 (ok) to an explicit call of
    SMTP.starttls(). This may allow a malicious MITM to
    perform a startTLS stripping attack if the client code
    does not explicitly check the response code for
    startTLS.

  - CVE-2016-5636 Issue #26171: Fix possible integer
    overflow and heap corruption in zipimporter.get_data().

  - CVE-2016-5699 Protocol injection can occur not only if
    an application sets a header based on user-supplied
    values, but also if the application ever tries to fetch
    a URL specified by an attacker (SSRF case) OR if the
    application ever accesses any malicious web server
    (redirection case).

For Debian 7 'Wheezy', these problems have been fixed in version
2.7.3-6+deb7u3.

We recommend that you upgrade your python2.7 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/06/msg00022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python2.7"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:idle-python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpython2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.7-minimal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");
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
if (deb_check(release:"7.0", prefix:"idle-python2.7", reference:"2.7.3-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libpython2.7", reference:"2.7.3-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7", reference:"2.7.3-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7-dbg", reference:"2.7.3-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7-dev", reference:"2.7.3-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7-doc", reference:"2.7.3-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7-examples", reference:"2.7.3-6+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python2.7-minimal", reference:"2.7.3-6+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
