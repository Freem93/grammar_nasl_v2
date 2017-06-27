# This script was automatically generated from Debian Security 
# Advisory DSA-1753. It is released under the Nessus Script 
# Licence.
#
# Debian Security Advisory DSA-1753 is (C) Software in the Public
# Interest, Inc; see http://www.debian.org/license for details.
#

include("compat.inc");

if (description)
{
  script_id(36046);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_xref(name:"DSA", value:"1753");

  script_name(english:"Debian DSA-1753-1 : iceweasel -- end-of-life announcement for Iceweasel in oldstable");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"As indicated in the Etch release notes, security support for the
Iceweasel version in the oldstable distribution (Etch) needed to be
stopped before the end of the regular security maintenance life
cycle."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1753"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to stable or switch to a still supported browser."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  # nb: worst base vector given this is a web browser.

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2009-2016 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/Debian/release")) exit(0, "The host is not running Debian.");
if (!get_kb_item("Host/Debian/dpkg-l")) exit(1, "Could not obtain the list of installed packages.");


flag = 0;
ref = "999.0.0.0-0etch1";               # nb: any high value should work.
if (deb_check(release:"4.0", prefix:"iceweasel", reference:ref)) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-dbg", reference:ref)) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-dom-inspector", reference:ref)) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-gnome-support", reference:ref)) flag++;

if (flag)
{
  if (report_verbosity > 0) 
  {
    report = "";
    foreach line (split(deb_report_get(), keep:FALSE))
    {
      if (max >!< line && "Should be :" >!< line) report += line + '\n';
    }
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
