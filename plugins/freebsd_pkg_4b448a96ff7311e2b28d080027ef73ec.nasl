#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2013 Jacques Vidrine and contributors
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
  script_id(69250);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/08/21 12:19:10 $");

  script_cve_id("CVE-2013-4206", "CVE-2013-4207", "CVE-2013-4208", "CVE-2013-4852");

  script_name(english:"FreeBSD : PuTTY -- Four security holes in versions before 0.63 (4b448a96-ff73-11e2-b28d-080027ef73ec)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Simon Tatham reports :

This [0.63] release fixes multiple security holes in previous versions
of PuTTY, which can allow an SSH-2 server to make PuTTY overrun or
underrun buffers and crash. [...]

These vulnerabilities can be triggered before host key verification,
which means that you are not even safe if you trust the server you
think you're connecting to, since it could be spoofed over the network
and the host key check would not detect this before the attack could
take place.

Additionally, when PuTTY authenticated with a user's private key, the
private key or information equivalent to it was accidentally kept in
PuTTY's memory for the rest of its run, where it could be retrieved by
other processes reading PuTTY's memory, or written out to swap files
or crash dumps. This release fixes that as well."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.tartarus.org/pipermail/putty-announce/2013/000018.html"
  );
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-modmul.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20c27652"
  );
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-bignum-division-by-zero.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1b0243c"
  );
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/private-key-not-wiped.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bdd07a8"
  );
  # http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-signature-stringlen.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4834e145"
  );
  # http://www.freebsd.org/ports/portaudit/4b448a96-ff73-11e2-b28d-080027ef73ec.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?234cb85b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:putty");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"putty<0.63")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
