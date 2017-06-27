# @DEPRECATED@
#
# This script has been deprecated as the associated advisory does not
# affect the stable release.
#
# Disabled on 2012/01/20.
#

# This script was automatically generated from Debian Security 
# Advisory DSA-119. It is released under the Nessus Script 
# Licence.
#
# Debian Security Advisory DSA-119 is (C) Software in the Public
# Interest, Inc; see http://www.debian.org/license for details.
#

include("compat.inc");

if (description)
{
  script_id(14956);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2012/01/21 02:41:31 $");

  script_cve_id("CVE-2002-0083");
  script_bugtraq_id(4241);
  script_osvdb_id(730);
  script_xref(name: "DSA", value: "119");

  script_name(english:"Debian DSA-119-1 : ssh -- local root exploit, remote client exploit");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Joost Pol reports that OpenSSH versions 2.0 through 3.0.2 have an
off-by-one bug in the channel allocation code.  This vulnerability can
be exploited by authenticated users to gain root privilege or by a
malicious server exploiting a client with this bug."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-119"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Since Debian 2.2 (potato) shipped with OpenSSH (the 'ssh' package)
version 1.2.3, it is not vulnerable to this exploit.  No fix is
required for Debian 2.2 (potato). 

The Debian unstable and testing archives do include a more recent
OpenSSH (ssh) package.  If you are running these pre-release
distributions you should ensure that you are running version
3.0.2p1-8, a patched version which was added to the unstable archive
today, or a later version."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2004-2012 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


# Deprecated.
exit(0, "The associated advisory does not affect the stable release.");
