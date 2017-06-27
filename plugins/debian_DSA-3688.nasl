#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3688. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93871);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2015-4000", "CVE-2015-7181", "CVE-2015-7182", "CVE-2015-7575", "CVE-2016-1938", "CVE-2016-1950", "CVE-2016-1978", "CVE-2016-1979", "CVE-2016-2834");
  script_osvdb_id(122331, 129797, 129798, 132305, 133669, 135603, 135604, 135718, 139466, 139467, 139468, 139469);
  script_xref(name:"DSA", value:"3688");

  script_name(english:"Debian DSA-3688-1 : nss - security update (Logjam) (SLOTH)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in NSS, the cryptography
library developed by the Mozilla project.

  - CVE-2015-4000
    David Adrian et al. reported that it may be feasible to
    attack Diffie-Hellman-based cipher suites in certain
    circumstances, compromising the confidentiality and
    integrity of data encrypted with Transport Layer
    Security (TLS).

  - CVE-2015-7181 CVE-2015-7182 CVE-2016-1950
    Tyson Smith, David Keeler, and Francis Gabriel
    discovered heap-based buffer overflows in the ASN.1 DER
    parser, potentially leading to arbitrary code execution.

  - CVE-2015-7575
    Karthikeyan Bhargavan discovered that TLS client
    implementation accepted MD5-based signatures for TLS 1.2
    connections with forward secrecy, weakening the intended
    security strength of TLS connections.

  - CVE-2016-1938
    Hanno Boeck discovered that NSS miscomputed the result
    of integer division for certain inputs. This could
    weaken the cryptographic protections provided by NSS.
    However, NSS implements RSA-CRT leak hardening, so RSA
    private keys are not directly disclosed by this issue.

  - CVE-2016-1978
    Eric Rescorla discovered a use-after-free vulnerability
    in the implementation of ECDH-based TLS handshakes, with
    unknown consequences.

  - CVE-2016-1979
    Tim Taubert discovered a use-after-free vulnerability in
    ASN.1 DER processing, with application-specific impact.

  - CVE-2016-2834
    Tyson Smith and Jed Davis discovered unspecified
    memory-safety bugs in NSS.

In addition, the NSS library did not ignore environment variables in
processes which underwent a SUID/SGID/AT_SECURE transition at process
start. In certain system configurations, this allowed local users to
escalate their privileges.

This update contains further correctness and stability fixes without
immediate security impact."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=583651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-4000"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7181"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7182"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1938"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1978"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/nss"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3688"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nss packages.

For the stable distribution (jessie), these problems have been fixed
in version 2:3.26-1+debu8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/05");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/06");
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
if (deb_check(release:"8.0", prefix:"libnss3", reference:"2:3.26-1+debu8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-1d", reference:"2:3.26-1+debu8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-dbg", reference:"2:3.26-1+debu8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-dev", reference:"2:3.26-1+debu8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libnss3-tools", reference:"2:3.26-1+debu8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
