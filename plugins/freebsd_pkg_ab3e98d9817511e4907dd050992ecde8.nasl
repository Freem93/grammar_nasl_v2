#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2016 Jacques Vidrine and contributors
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
  script_id(79957);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/10 13:36:30 $");

  script_cve_id("CVE-2014-8500", "CVE-2014-8680");
  script_bugtraq_id(71590);
  script_xref(name:"FreeBSD", value:"SA-14:29.bind");

  script_name(english:"FreeBSD : bind -- denial of service vulnerability (ab3e98d9-8175-11e4-907d-d050992ecde8)");
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
"ISC reports :

We have today posted updated versions of 9.9.6 and 9.10.1 to address a
significant security vulnerability in DNS resolution. The flaw was
discovered by Florian Maury of ANSSI, and applies to any recursive
resolver that does not support a limit on the number of recursions.
[CERTFR-2014-AVI-512], [USCERT VU#264212]

A flaw in delegation handling could be exploited to put named into an
infinite loop, in which each lookup of a name server triggered
additional lookups of more name servers. This has been addressed by
placing limits on the number of levels of recursion named will allow
(default 7), and on the number of queries that it will send before
terminating a recursive query (default 50). The recursion depth limit
is configured via the max-recursion-depth option, and the query limit
via the max-recursion-queries option. For more information, see the
security advisory at https://kb.isc.org/article/AA-01216/.
[CVE-2014-8500] [RT #37580]

In addition, we have also corrected a potential security vulnerability
in the GeoIP feature in the 9.10.1 release only. For more information
on this issue, see the security advisory at
https://kb.isc.org/article/AA-01217. [CVE-2014-8680]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.isc.org/blogs/important-security-advisory-posted/"
  );
  # http://www.freebsd.org/ports/portaudit/ab3e98d9-8175-11e4-907d-d050992ecde8.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?891104a4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind96");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind96-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind98");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind98-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind99");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bind99-base");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"bind99<9.9.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind99-base<9.9.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind98>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind98-base>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind96>0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bind96-base>0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
