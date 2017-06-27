#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-235-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83907);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/04/28 18:15:20 $");

  script_cve_id("CVE-2011-0188", "CVE-2011-2705", "CVE-2012-4522", "CVE-2013-0256", "CVE-2013-2065", "CVE-2015-1855");
  script_bugtraq_id(46950, 46966, 49015, 56115, 57785, 59881, 74446);
  script_osvdb_id(93414, 120541);

  script_name(english:"Debian DLA-235-1 : ruby1.9.1 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2011-0188 The VpMemAlloc function in bigdecimal.c in the
BigDecimal class in Ruby 1.9.2-p136 and earlier, as used on Apple Mac
OS X before 10.6.7 and other platforms, does not properly allocate
memory, which allows context-dependent attackers to execute arbitrary
code or cause a denial of service (application crash) via vectors
involving creation of a large BigDecimal value within a 64-bit
process, related to an 'integer truncation issue.'

CVE-2011-2705 use upstream SVN r32050 to modify PRNG state to prevent
random number sequence repeatation at forked child process which has
same pid. Reported by Eric Wong.

CVE-2012-4522 The rb_get_path_check function in file.c in Ruby 1.9.3
before patchlevel 286 and Ruby 2.0.0 before r37163 allows
context-dependent attackers to create files in unexpected locations or
with unexpected names via a NUL byte in a file path.

CVE-2013-0256 darkfish.js in RDoc 2.3.0 through 3.12 and 4.x before
4.0.0.preview2.1, as used in Ruby, does not properly generate
documents, which allows remote attackers to conduct cross-site
scripting (XSS) attacks via a crafted URL.

CVE-2013-2065 (1) DL and (2) Fiddle in Ruby 1.9 before 1.9.3
patchlevel 426, and 2.0 before 2.0.0 patchlevel 195, do not perform
taint checking for native functions, which allows context-dependent
attackers to bypass intended $SAFE level restrictions.

CVE-2015-1855 OpenSSL extension hostname matching implementation
violates RFC 6125

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/05/msg00020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/ruby1.9.1"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libruby1.9.1-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtcltk-ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ri1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-elisp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby1.9.1-full");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libruby1.9.1", reference:"1.9.2.0-2+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libruby1.9.1-dbg", reference:"1.9.2.0-2+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libtcltk-ruby1.9.1", reference:"1.9.2.0-2+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"ri1.9.1", reference:"1.9.2.0-2+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.9.1", reference:"1.9.2.0-2+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.9.1-dev", reference:"1.9.2.0-2+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.9.1-elisp", reference:"1.9.2.0-2+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.9.1-examples", reference:"1.9.2.0-2+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"ruby1.9.1-full", reference:"1.9.2.0-2+deb6u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
