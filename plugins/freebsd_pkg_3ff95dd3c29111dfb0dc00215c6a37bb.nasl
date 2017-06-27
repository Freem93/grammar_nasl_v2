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
  script_id(49273);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/09 15:44:46 $");

  script_cve_id("CVE-2010-3082");
  script_bugtraq_id(43116);

  script_name(english:"FreeBSD : django -- XSS vulnerability (3ff95dd3-c291-11df-b0dc-00215c6a37bb)");
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
"Django project reports :

The provided template tag for inserting the CSRF token into forms --
{% csrf_token %} -- explicitly trusts the cookie value, and displays
it as-is. Thus, an attacker who is able to tamper with the value of
the CSRF cookie can cause arbitrary content to be inserted, unescaped,
into the outgoing HTML of the form, enabling cross-site scripting
(XSS) attacks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://xforce.iss.net/xforce/xfdb/61729"
  );
  # http://www.freebsd.org/ports/portaudit/3ff95dd3-c291-11df-b0dc-00215c6a37bb.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0409229e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py23-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py23-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py24-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py24-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py25-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py25-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py26-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py30-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py30-django-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py31-django-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"py23-django>1.2<1.2.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django>1.2<1.2.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django>1.2<1.2.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django>1.2<1.2.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django>1.2<1.2.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django>1.2<1.2.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py23-django-devel<13698,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py24-django-devel<13698,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py25-django-devel<13698,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py26-django-devel<13698,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py30-django-devel<13698,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py31-django-devel<13698,1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
