# @DEPRECATED@
#
# This script has been deprecated as the associated advisory does not 
# have any package tests.
#
# Disabled on 2012/01/20.
#

# This script was automatically generated from Debian Security 
# Advisory DSA-1605. It is released under the Nessus Script 
# Licence.
#
# Debian Security Advisory DSA-1605 is (C) Software in the Public
# Interest, Inc; see http://www.debian.org/license for details.
#

include("compat.inc");

if (description)
{
  script_id(33452);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2012/12/28 21:13:28 $");

  script_cve_id("CVE-2008-1447");
  script_osvdb_id(47232, 47916, 47926, 47927, 48245);
  script_xref(name:"DSA", value:"1605");
  script_xref(name:"CERT", value:"800113");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"Debian DSA-1605-1 : glibc - DNS cache poisoning");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Kaminsky discovered that properties inherent to the DNS protocol
lead to practical DNS spoofing and cache poisoning attacks.  Among
other things, successful attacks can lead to misdirected web traffic
and email rerouting."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"At this time, it is not possible to implement the recommended
countermeasures in the GNU libc stub resolver.  The following
workarounds are available :

  1. Install a local BIND 9 resolver on the host, possibly
     in forward-only mode.  BIND 9 will then use source port
     randomization when sending queries over the network.
     (Other caching resolvers can be used instead.)

  2. Rely on IP address spoofing protection if available.  
     Successful attacks must spoof the address of one of the
     resolvers, which may not be possible if the network is 
     guarded properly against IP spoofing attacks (both from 
    internal and external sources).

This DSA will be updated when patches for hardening the stub resolver
are available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/10");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is (C) 2008-2012 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


# Deprecated.
exit(0, "The associated advisory does not have any package tests.");
