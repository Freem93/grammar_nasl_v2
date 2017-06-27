#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1617. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33737);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2015/05/29 04:35:54 $");

  script_cve_id("CVE-2008-1447");
  script_bugtraq_id(30131);
  script_xref(name:"DSA", value:"1617");
  script_xref(name:"IAVA", value:"2008-A-0045");

  script_name(english:"Debian DSA-1617-1 : refpolicy - incompatible policy");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In DSA-1603-1, Debian released an update to the BIND 9 domain name
server, which introduced UDP source port randomization to mitigate the
threat of DNS cache poisoning attacks (identified by the Common
Vulnerabilities and Exposures project as CVE-2008-1447 ). The fix,
while correct, was incompatible with the version of SELinux Reference
Policy shipped with Debian Etch, which did not permit a process
running in the named_t domain to bind sockets to UDP ports other than
the standard 'domain' port (53). The incompatibility affects both the
'targeted' and 'strict' policy packages supplied by this version of
refpolicy.

This update to the refpolicy packages grants the ability to bind to
arbitrary UDP ports to named_t processes. When installed, the updated
packages will attempt to update the bind policy module on systems
where it had been previously loaded and where the previous version of
refpolicy was 0.0.20061018-5 or below.

Because the Debian refpolicy packages are not yet designed with policy
module upgradeability in mind, and because SELinux-enabled Debian
systems often have some degree of site-specific policy customization,
it is difficult to assure that the new bind policy can be successfully
upgraded. To this end, the package upgrade will not abort if the bind
policy update fails. The new policy module can be found at
/usr/share/selinux/refpolicy-targeted/bind.pp after installation.
Administrators wishing to use the bind service policy can reconcile
any policy incompatibilities and install the upgrade manually
thereafter. A more detailed discussion of the corrective procedure may
be found on
https://wiki.debian.org/SELinux/Issues/BindPortRandomization."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=490271"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1447"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/SELinux/Issues/BindPortRandomization"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1617"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the refpolicy packages.

For the stable distribution (etch), this problem has been fixed in
version 0.0.20061018-5.1+etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:refpolicy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/28");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"selinux-policy-refpolicy-dev", reference:"0.0.20061018-5.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"selinux-policy-refpolicy-doc", reference:"0.0.20061018-5.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"selinux-policy-refpolicy-src", reference:"0.0.20061018-5.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"selinux-policy-refpolicy-strict", reference:"0.0.20061018-5.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"selinux-policy-refpolicy-targeted", reference:"0.0.20061018-5.1+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
