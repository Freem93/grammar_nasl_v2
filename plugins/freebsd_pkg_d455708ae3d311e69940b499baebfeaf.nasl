#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2017 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include("compat.inc");

if (description)
{
  script_id(96821);
  script_version("$Revision: 3.9 $");
  script_cvs_date("$Date: 2017/05/15 14:02:24 $");

  script_cve_id("CVE-2016-7055", "CVE-2017-3730", "CVE-2017-3731", "CVE-2017-3732");

  script_name(english:"FreeBSD : OpenSSL -- multiple vulnerabilities (d455708a-e3d3-11e6-9940-b499baebfeaf)");
  script_summary(english:"Checks for updated packages in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FreeBSD host is missing one or more security-related
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The OpenSSL project reports :

- Truncated packet could crash via OOB read (CVE-2017-3731) Severity:
Moderate If an SSL/TLS server or client is running on a 32-bit host,
and a specific cipher is being used, then a truncated packet can cause
that server or client to perform an out-of-bounds read, usually
resulting in a crash.

- Bad (EC)DHE parameters cause a client crash (CVE-2017-3730)
Severity: Moderate If a malicious server supplies bad parameters for a
DHE or ECDHE key exchange then this can result in the client
attempting to dereference a NULL pointer leading to a client crash.
This could be exploited in a Denial of Service attack.

- BN_mod_exp may produce incorrect results on x86_64 (CVE-2017-3732)
Severity: Moderate There is a carry propagating bug in the x86_64
Montgomery squaring procedure. No EC algorithms are affected. Analysis
suggests that attacks against RSA and DSA as a result of this defect
would be very difficult to perform and are not believed likely.
Attacks against DH are considered just feasible (although very
difficult) because most of the work necessary to deduce information
about a private key may be performed offline. The amount of resources
required for such an attack would be very significant and likely only
accessible to a limited number of attackers. An attacker would
additionally need online access to an unpatched system using the
target private key in a scenario with persistent DH parameters and a
private key that is shared between multiple clients. For example this
can occur by default in OpenSSL DHE based SSL/TLS ciphersuites. Note:
This issue is very similar to CVE-2015-3193 but must be treated as a
separate problem.

- Montgomery multiplication may produce incorrect results
(CVE-2016-7055) Severity: Low There is a carry propagating bug in the
Broadwell-specific Montgomery multiplication procedure that handles
input lengths divisible by, but longer than 256 bits. (OpenSSL 1.0.2
only) This issue was previously fixed in 1.1.0c"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.openssl.org/news/secadv/20170126.txt"
  );
  # http://www.freebsd.org/ports/portaudit/d455708a-e3d3-11e6-9940-b499baebfeaf.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bef32b94"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c6-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:linux-c7-openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
  script_family(english:"FreeBSD Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"openssl<1.0.2k,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"openssl-devel<1.1.0d")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c6-openssl<1.0.1e_13")) flag++;
if (pkg_test(save_report:TRUE, pkg:"linux-c7-openssl-libs<1.0.1e_3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
