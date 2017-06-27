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
  script_id(62068);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/21 23:43:36 $");

  script_cve_id("CVE-2012-4001", "CVE-2012-4360");

  script_name(english:"FreeBSD : mod_pagespeed -- multiple vulnerabilities (178ba4ea-fd40-11e1-b2ae-001fd0af1a4c)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Google Reports :

mod_pagespeed 0.10.22.6 is a security update that fixes two critical
issues that affect earlier versions :

- CVE-2012-4001, a problem with validation of own host name.

- CVE-2012-4360, a cross-site scripting attack, which affects versions
starting from 0.10.19.1.

The effect of the first problem is that it is possible to confuse
mod_pagespeed about its own host name, and to trick it into fetching
resources from other machines. This could be an issue if the HTTP
server has access to machines that are not otherwise publicly visible.

The second problem would permit a hostile third party to execute
JavaScript in users' browsers in context of the domain running
mod_pagespeed, which could permit interception of users' cookies or
data on the site.

Because of the severity of the two problems, users are strongly
encouraged to update immediately.

Behavior Changes in the Update :

As part of the fix to the first issue, mod_pagespeed will not fetch
resources from machines other than localhost if they are not
explicitly mentioned in the configuration. This means that if you need
resources on the server's domain to be handled by some other system,
you'll need to explicitly use ModPagespeedMapOriginDomain or
ModPagespeedDomain to authorize that."
  );
  # https://developers.google.com/speed/docs/mod_pagespeed/announce-0.10.22.6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6337af0f"
  );
  # http://www.freebsd.org/ports/portaudit/178ba4ea-fd40-11e1-b2ae-001fd0af1a4c.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?546a478b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_pagespeed");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/13");
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

if (pkg_test(save_report:TRUE, pkg:"mod_pagespeed<0.10.22.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
