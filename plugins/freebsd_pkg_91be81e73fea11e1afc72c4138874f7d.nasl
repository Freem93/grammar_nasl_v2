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
  script_id(57552);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/06/22 00:02:02 $");

  script_cve_id("CVE-2011-4815", "CVE-2011-4838", "CVE-2011-5036", "CVE-2011-5037");

  script_name(english:"FreeBSD : Multiple implementations -- DoS via hash algorithm collision (91be81e7-3fea-11e1-afc7-2c4138874f7d)");
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
"oCERT reports :

A variety of programming languages suffer from a denial-of-service
(DoS) condition against storage functions of key/value pairs in hash
data structures, the condition can be leveraged by exploiting
predictable collisions in the underlying hashing algorithms.

The issue finds particular exposure in web server applications and/or
frameworks. In particular, the lack of sufficient limits for the
number of parameters in POST requests in conjunction with the
predictable collision properties in the hashing functions of the
underlying languages can render web applications vulnerable to the DoS
condition. The attacker, using specially crafted HTTP requests, can
lead to a 100% of CPU usage which can last up to several hours
depending on the targeted application and server performance, the
amplification effect is considerable and requires little bandwidth and
time on the attacker side.

The condition for predictable collisions in the hashing functions has
been reported for the following language implementations : Java,
JRuby, PHP, Python, Rubinius, Ruby. In the case of the Ruby language,
the 1.9.x branch is not affected by the predictable collision
condition since this version includes a randomization of the hashing
function.

The vulnerability outlined in this advisory is practically identical
to the one reported in 2003 and described in the paper Denial of
Service via Algorithmic Complexity Attacks which affected the Perl
language."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.ocert.org/advisories/ocert-2011-003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nruns.com/_downloads/advisory28122011.pdf"
  );
  # http://www.freebsd.org/ports/portaudit/91be81e7-3fea-11e1-afc7-2c4138874f7d.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c4e600a6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:jruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ruby+nopthreads");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ruby+nopthreads+oniguruma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ruby+oniguruma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:v8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/16");
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

if (pkg_test(save_report:TRUE, pkg:"jruby<1.6.5.1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ruby<1.8.7.357,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ruby+nopthreads<1.8.7.357,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ruby+nopthreads+oniguruma<1.8.7.357,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ruby+oniguruma<1.8.7.357,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"rubygem-rack<1.3.6,3")) flag++;
if (pkg_test(save_report:TRUE, pkg:"v8<3.8.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"redis<=2.4.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"node<0.6.7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
