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
  script_id(90233);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/13 20:45:09 $");

  script_cve_id("CVE-2016-3176");

  script_name(english:"FreeBSD : salt -- Insecure configuration of PAM external authentication service (6d25c306-f3bb-11e5-92ce-002590263bf5)");
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
"SaltStack reports :

This issue affects all Salt versions prior to 2015.8.8/2015.5.10 when
PAM external authentication is enabled. This issue involves passing an
alternative PAM authentication service with a command that is sent to
LocalClient, enabling the attacker to bypass the configured
authentication service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.saltstack.com/en/latest/topics/releases/2015.8.8.html"
  );
  # http://www.freebsd.org/ports/portaudit/6d25c306-f3bb-11e5-92ce-002590263bf5.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d152f82"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py27-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py32-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py33-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py34-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:py35-salt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"py27-salt<2015.5.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py27-salt>=2015.8.0<2015.8.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-salt<2015.5.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py32-salt>=2015.8.0<2015.8.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-salt<2015.5.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py33-salt>=2015.8.0<2015.8.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-salt<2015.5.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py34-salt>=2015.8.0<2015.8.8")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-salt<2015.5.10")) flag++;
if (pkg_test(save_report:TRUE, pkg:"py35-salt>=2015.8.0<2015.8.8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
