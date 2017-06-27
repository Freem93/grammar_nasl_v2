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

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96223);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_cve_id("CVE-2016-9422", "CVE-2016-9423", "CVE-2016-9424", "CVE-2016-9425", "CVE-2016-9426", "CVE-2016-9428", "CVE-2016-9429", "CVE-2016-9430", "CVE-2016-9431", "CVE-2016-9432", "CVE-2016-9433", "CVE-2016-9434", "CVE-2016-9435", "CVE-2016-9436", "CVE-2016-9437", "CVE-2016-9438", "CVE-2016-9439", "CVE-2016-9440", "CVE-2016-9441", "CVE-2016-9442", "CVE-2016-9443", "CVE-2016-9622", "CVE-2016-9623", "CVE-2016-9624", "CVE-2016-9625", "CVE-2016-9626", "CVE-2016-9627", "CVE-2016-9628", "CVE-2016-9629", "CVE-2016-9630", "CVE-2016-9631", "CVE-2016-9632", "CVE-2016-9633");

  script_name(english:"FreeBSD : w3m -- multiple vulnerabilities (eafa3aec-211b-4dd4-9b8a-a664a3f0917a)");
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
"Multiple remote code execution and denial of service conditions
present."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2016/q4/452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2016/q4/516"
  );
  # http://www.freebsd.org/ports/portaudit/eafa3aec-211b-4dd4-9b8a-a664a3f0917a.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da25c363"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-w3m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ja-w3m-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:w3m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:w3m-img");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"w3m<0.5.3.20170102")) flag++;
if (pkg_test(save_report:TRUE, pkg:"w3m-img<0.5.3.20170102")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-w3m<0.5.3.20170102")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ja-w3m-img<0.5.3.20170102")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
