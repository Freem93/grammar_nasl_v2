# @DEPRECATED@
#
# This script has been deprecated as the associated advisory does not 
# have any package tests.
#
# Disabled on 2012/01/20.
#

# This script was automatically generated from Debian Security 
# Advisory DSA-1604. It is released under the Nessus Script 
# Licence.
#
# Debian Security Advisory DSA-1604 is (C) Software in the Public
# Interest, Inc; see http://www.debian.org/license for details.
#

include("compat.inc");

if (description)
{
  script_id(33451);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/06/03 16:47:17 $");

  script_cve_id("CVE-2008-1447");
  script_osvdb_id(47232, 47916, 47926, 47927, 48245);
  script_xref(name:"CERT", value:"800113");
  script_xref(name:"IAVA", value:"2008-A-0045");
  script_xref(name:"DSA", value:"1603");
  script_xref(name:"DSA", value:"1604");

  script_name(english:"Debian DSA-1604-1 : bind - DNS cache poisoning");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Kaminsky discovered that properties inherent to the DNS protocol
lead to practical DNS cache poisoning attacks.  Among other things,
successful attacks can lead to misdirected web traffic and email
rerouting."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"The BIND 8 legacy code base could not be updated to include the
recommended countermeasure (source port randomization, see DSA-1603-1
for details).  There are two ways to deal with this situation :

  1. Upgrade to BIND 9 (or another implementation with 
     source port randomization).  The documentation included
     with BIND 9 contains a migration guide. 

  2. Configure the BIND 8 resolver to forward queries to a 
     BIND 9 resolver.  Provided that the network between 
     both resolvers is trusted, this protects the BIND 8 
     resolver from cache poisoning attacks (to the same 
     degree that the BIND 9 resolver is protected). 

This problem does not apply to BIND 8 when used exclusively as an
authoritative DNS server.  It is theoretically possible to safely use
BIND 8 in this way, but updating to BIND 9 is strongly recommended. 
BIND 8 (that is, the bind package) will be removed from the etch
distribution in a future point release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/10");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2008-2013 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


# Deprecated.
exit(0, "The associated advisory does not have any package tests.");
