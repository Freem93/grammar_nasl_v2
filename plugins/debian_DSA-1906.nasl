# @DEPRECATED@
#
# This script has been deprecated as the associated advisory does not 
# have any package tests.
#
# Disabled on 2012/01/20.
#

# This script was automatically generated from Debian Security 
# Advisory DSA-1906. It is released under the Nessus Script 
# Licence.
#
# Debian Security Advisory DSA-1906 is (C) Software in the Public
# Interest, Inc; see http://www.debian.org/license for details.
#

include("compat.inc");

if (description)
{
  script_id(44771);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/01/21 02:41:31 $");

  script_xref(name:"DSA", value:"1906");

  script_name(english:"Debian DSA-1906-1 : clamav - End-of-life announcement for clamav in stable and oldstable");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security support for clamav, an anti-virus utility for Unix, has been
discontinued for the stable distribution (lenny) and the oldstable
distribution (etch).  Clamav Upstream has stopped supporting the
releases in etch and lenny.  Also, it is not easily possible to
receive signature updates for the virus scanner with our released
versions anymore."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1906"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All clamav users should consider switching to the version in
debian-volatile, which receives regular updates and security support
on a best effort basis. 

For more information on debian-volatile, please visit
http://www.debian.org/volatile/"
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2010-2012 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


# Deprecated.
exit(0, "The associated advisory does not have any package tests.");
