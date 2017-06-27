#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1603. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33450);
  script_version("$Revision: 1.32 $");
  script_cvs_date("$Date: 2016/04/29 04:40:48 $");

  script_cve_id("CVE-2008-1447", "CVE-2008-4194");
  script_osvdb_id(47232, 47916, 47926, 47927, 48245);
  script_xref(name:"CERT", value:"800113");
  script_xref(name:"IAVA", value:"2008-A-0045");
  script_xref(name:"DSA", value:"1603");

  script_name(english:"Debian DSA-1603-1 : bind9 - DNS cache poisoning");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dan Kaminsky discovered that properties inherent to the DNS protocol
lead to practical DNS cache poisoning attacks. Among other things,
successful attacks can lead to misdirected web traffic and email
rerouting.

This update changes Debian's BIND 9 packages to implement the
recommended countermeasure: UDP query source port randomization. This
change increases the size of the space from which an attacker has to
guess values in a backwards-compatible fashion and makes successful
attacks significantly more difficult.

Note that this security update changes BIND network behavior in a
fundamental way, and the following steps are recommended to ensure a
smooth upgrade.

1. Make sure that your network configuration is compatible with source
port randomization. If you guard your resolver with a stateless packet
filter, you may need to make sure that no non-DNS services listen on
the 1024--65535 UDP port range and open it at the packet filter. For
instance, packet filters based on etch's Linux 2.6.18 kernel only
support stateless filtering of IPv6 packets, and therefore pose this
additional difficulty. (If you use IPv4 with iptables and ESTABLISHED
rules, networking changes are likely not required.)

2. Install the BIND 9 upgrade, using 'apt-get update' followed by
'apt-get install bind9'. Verify that the named process has been
restarted and answers recursive queries. (If all queries result in
timeouts, this indicates that networking changes are necessary; see
the first step.)

3. Verify that source port randomization is active. Check that the
/var/log/daemon.log file does not contain messages of the following
form

named[6106]: /etc/bind/named.conf.options:28: using specific
query-source port suppresses port randomization and can be insecure.

right after the 'listening on IPv6 interface' and 'listening on IPv4
interface' messages logged by BIND upon startup. If these messages are
present, you should remove the indicated lines from the configuration,
or replace the port numbers contained within them with '*' sign (e.g.,
replace 'port 53' with 'port *').

For additional certainty, use tcpdump or some other network monitoring
tool to check for varying UDP source ports. If there is a NAT device
in front of your resolver, make sure that it does not defeat the
effect of source port randomization.

4. If you cannot activate source port randomization, consider
configuring BIND 9 to forward queries to a resolver which can,
possibly over a VPN such as OpenVPN to create the necessary trusted
network link. (Use BIND's forward-only mode in this case.)

Other caching resolvers distributed by Debian (PowerDNS, MaraDNS,
Unbound) already employ source port randomization, and no updated
packages are needed. BIND 9.5 up to and including version
1:9.5.0.dfsg-4 only implements a weak form of source port
randomization and needs to be updated as well. For information on BIND
8, see DSA-1604-1, and for the status of the libc stub resolver, see
DSA-1605-1.

The updated bind9 packages contain changes originally scheduled for
the next stable point release, including the changed IP address of
L.ROOT-SERVERS.NET (Debian bug # 449148)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/449148"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1603"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the bind9 package.

For the stable distribution (etch), this problem has been fixed in
version 9.3.4-2etch3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/10");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"bind9", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"bind9-doc", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"bind9-host", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"dnsutils", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libbind-dev", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libbind9-0", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libdns22", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libisc11", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libisccc0", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"libisccfg1", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"liblwres9", reference:"9.3.4-2etch3")) flag++;
if (deb_check(release:"4.0", prefix:"lwresd", reference:"9.3.4-2etch3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
