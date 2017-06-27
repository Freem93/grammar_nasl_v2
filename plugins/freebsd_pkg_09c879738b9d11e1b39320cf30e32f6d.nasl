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
  script_id(58828);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/21 23:43:34 $");

  script_cve_id("CVE-2012-0465", "CVE-2012-0466");

  script_name(english:"FreeBSD : bugzilla -- multiple vulnerabilities (09c87973-8b9d-11e1-b393-20cf30e32f6d)");
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
"A Bugzilla Security Advisory reports : The following security issues
have been discovered in Bugzilla : Unauthorized Access Due to a lack
of proper validation of the X-FORWARDED-FOR header of an
authentication request, an attacker could bypass the current lockout
policy used for protection against brute- force password discovery.
This vulnerability can only be exploited if the 'inbound_proxies'
parameter is set. Cross Site Scripting A JavaScript template used by
buglist.cgi could be used by a malicious script to permit an attacker
to gain access to some information about bugs he would not normally be
allowed to see, using the victim's credentials. To be exploitable, the
victim must be logged in when visiting the attacker's malicious page.

All affected installations are encouraged to upgrade as soon as
possible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=728639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=745397"
  );
  # http://www.freebsd.org/ports/portaudit/09c87973-8b9d-11e1-b393-20cf30e32f6d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?077999b7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/23");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"bugzilla>=3.6.0<3.6.9")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bugzilla>=4.0.0<4.0.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
