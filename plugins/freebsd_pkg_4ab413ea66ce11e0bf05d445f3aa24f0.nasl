#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2014 Jacques Vidrine and contributors
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
  script_id(53440);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/08/20 15:05:36 $");

  script_cve_id("CVE-2011-0281", "CVE-2011-0282", "CVE-2011-0283");

  script_name(english:"FreeBSD : krb5 -- MITKRB5-SA-2011-002, KDC vulnerable to hang when using LDAP back end (4ab413ea-66ce-11e0-bf05-d445f3aa24f0)");
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
"An advisory published by the MIT Kerberos team says :

The MIT krb5 Key Distribution Center (KDC) daemon is vulnerable to
denial of service attacks from unauthenticated remote attackers.
CVE-2011-0281 and CVE-2011-0282 occur only in KDCs using LDAP back
ends, but CVE-2011-0283 occurs in all krb5-1.9 KDCs.

Exploit code is not known to exist, but the vulnerabilities are easy
to trigger manually. The trigger for CVE-2011-0281 has already been
disclosed publicly, but that fact might not be obvious to casual
readers of the message in which it was disclosed. The triggers for
CVE-2011-0282 and CVE-2011-0283 have not yet been disclosed publicly,
but they are also trivial.

CVE-2011-0281: An unauthenticated remote attacker can cause a KDC
configured with an LDAP back end to become completely unresponsive
until restarted.

CVE-2011-0282: An unauthenticated remote attacker can cause a KDC
configured with an LDAP back end to crash with a NULL pointer
dereference.

CVE-2011-0283: An unauthenticated remote attacker can cause a krb5-1.9
KDC with any back end to crash with a NULL pointer dereference."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://web.mit.edu/kerberos/advisories/MITKRB5-SA-2011-002.txt"
  );
  # http://www.freebsd.org/ports/portaudit/4ab413ea-66ce-11e0-bf05-d445f3aa24f0.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?395dc9ac"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"krb5>=1.7<1.7.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"krb5>=1.8<=1.8.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"krb5=1.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
