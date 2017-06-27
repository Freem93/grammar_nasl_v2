#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2015 Jacques Vidrine and contributors
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
  script_id(19179);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/13 14:37:10 $");

  script_cve_id("CVE-2005-0667");

  script_name(english:"FreeBSD : sylpheed -- buffer overflow in header processing (f8536143-9bc4-11d9-b8b3-000a95bc6fae)");
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
"The Sylpheed website states :

A buffer overflow which occurred when replying to a message with
certain headers which contain non-ascii characters was fixed."
  );
  # http://sylpheed.good-day.net/index.cgi.en#changes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6911b70"
  );
  # http://www.freebsd.org/ports/portaudit/f8536143-9bc4-11d9-b8b3-000a95bc6fae.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?06bba921"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sylpheed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sylpheed-claws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:sylpheed-gtk2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"sylpheed>=0.8.*<1.0.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sylpheed>=1.9.*<1.9.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sylpheed-claws>=0.8.*<1.0.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sylpheed-claws>=1.9.*<1.9.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sylpheed-gtk2>=0.8.*<1.0.3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"sylpheed-gtk2>=1.9.*<1.9.5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
