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
  script_id(22504);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2014/04/02 10:44:39 $");

  script_cve_id("CVE-2006-5178");
  script_bugtraq_id(20326);
  script_xref(name:"Secunia", value:"22235");

  script_name(english:"FreeBSD : php -- open_basedir Race Condition Vulnerability (edabe438-542f-11db-a5ae-00508d6a62df)");
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
"Stefan Esser reports :

PHP's open_basedir feature is meant to disallow scripts to access
files outside a set of configured base directories. The checks for
this are placed within PHP functions dealing with files before the
actual open call is performed.

Obviously there is a little span of time between the check and the
actual open call. During this time span the checked path could have
been altered and point to a file that is forbidden to be accessed due
to open_basedir restrictions.

Because the open_basedir restrictions often not call PHP functions but
3rd party library functions to actually open the file it is impossible
to close this time span in a general way. It would only be possible to
close it when PHP handles the actual opening on it's own.

While it seems hard to change the path during this little time span it
is very simple with the use of the symlink() function combined with a
little trick. PHP's symlink() function ensures that source and target
of the symlink operation are allowed by open_basedir restrictions (and
safe_mode). However it is possible to point a symlink to any file by
the use of mkdir(), unlink() and at least two symlinks."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.hardened-php.net/advisory_082006.132.html"
  );
  # http://www.freebsd.org/ports/portaudit/edabe438-542f-11db-a5ae-00508d6a62df.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b29a622"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mod_php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-dtc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php4-nms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-cgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-dtc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-horde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:php5-nms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"php4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php-suhosin<0.9.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-cli>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-cli>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-cli>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-cli>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-cgi>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-cgi>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-cgi>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-cgi>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-dtc>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-dtc>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-dtc>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-dtc>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-horde>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-horde>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-horde>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-horde>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-nms>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php4-nms>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-nms>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"php5-nms>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php4>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php4>=5<5.1.6_2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php5>=4<4.4.4_1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mod_php5>=5<5.1.6_2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
