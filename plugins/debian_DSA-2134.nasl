# @DEPRECATED@
#
# This script has been deprecated as the associated advisory does not 
# have any package tests.
#
# Disabled on 2012/01/20.
#

# This script was automatically generated from Debian Security 
# Advisory DSA-2133. It is released under the Nessus Script 
# Licence.
#
# Debian Security Advisory DSA-2133 is (C) Software in the Public
# Interest, Inc; see http://www.debian.org/license for details.
#

include("compat.inc");

if (description)
{
  script_id(51396);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2012/01/21 02:41:31 $");

  script_xref(name:"DSA", value:"2134");

  script_name(english:"Debian DSA-2134-1 : upcoming changes in advisory format");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Traditionally Debian Security Advisories have included MD5 check sums
of the updated packages.  This was introduced at a time when apt
didn't exist yet and BIND was at version 4. 

Since apt cryptographically enforces the integrity of the archive for
quite some time now, we've decided to finally drop the hash values
from our advisory mails. 

We'll also change some details of the advisory format in the upcoming
months."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2134"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2011-2012 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


# Deprecated.
exit(0, "The associated advisory does not have any package tests.");
