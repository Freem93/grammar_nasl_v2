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
  script_id(60151);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/21 23:52:44 $");

  script_cve_id("CVE-2012-1968", "CVE-2012-1969");

  script_name(english:"FreeBSD : bugzilla -- multiple vulnerabilities (58253655-d82c-11e1-907c-20cf30e32f6d)");
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
have been discovered in Bugzilla : Information Leak Versions: 4.1.1 to
4.2.1, 4.3.1

In HTML bugmails, all bug IDs and attachment IDs are linkified, and
hovering these links displays a tooltip with the bug summary or the
attachment description if the user is allowed to see the bug or
attachment. But when validating user permissions when generating the
email, the permissions of the user who edited the bug were taken into
account instead of the permissions of the addressee. This means that
confidential information could be disclosed to the addressee if the
other user has more privileges than the addressee. Plain text bugmails
are not affected as bug and attachment IDs are not linkified.
Information Leak Versions: 2.17.5 to 3.6.9, 3.7.1 to 4.0.6, 4.1.1 to
4.2.1, 4.3.1

The description of a private attachment could be visible to a user who
hasn't permissions to access this attachment if the attachment ID is
mentioned in a public comment in a bug that the user can see."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=777398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.mozilla.org/show_bug.cgi?id=777586"
  );
  # http://www.freebsd.org/ports/portaudit/58253655-d82c-11e1-907c-20cf30e32f6d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?182938f9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:bugzilla");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/30");
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

if (pkg_test(save_report:TRUE, pkg:"bugzilla>=3.6.0<3.6.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bugzilla>=4.0.0<4.0.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"bugzilla>=4.2.0<4.2.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
