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
  script_id(66968);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/08/01 10:50:40 $");

  script_cve_id("CVE-2013-2174");

  script_name(english:"FreeBSD : cURL library -- heap corruption in curl_easy_unescape (01cf67b3-dc3b-11e2-a6cd-c48508086173)");
  script_summary(english:"Checks for updated package in pkg_info output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote FreeBSD host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"cURL developers report :

libcurl is vulnerable to a case of bad checking of the input data
which may lead to heap corruption.

The function curl_easy_unescape() decodes URL-encoded strings to raw
binary data. URL-encoded octets are represented with %HH combinations
where HH is a two-digit hexadecimal number. The decoded string is
written to an allocated memory area that the function returns to the
caller.

The function takes a source string and a length parameter, and if the
length provided is 0 the function will instead use strlen() to figure
out how much data to parse.

The '%HH' parser wrongly only considered the case where a zero byte
would terminate the input. If a length-limited buffer was passed in
which ended with a '%' character which was followed by two hexadecimal
digits outside of the buffer libcurl was allowed to parse alas without
a terminating zero, libcurl would still parse that sequence as well.
The counter for remaining data to handle would then be decreased too
much and wrap to become a very large integer and the copying would go
on too long and the destination buffer that is allocated on the heap
would get overwritten.

We consider it unlikely that programs allow user-provided strings
unfiltered into this function. Also, only the not zero-terminated
input string use case is affected by this flaw. Exploiting this flaw
for gain is probably possible for specific circumstances but we
consider the general risk for this to be low.

The curl command line tool is not affected by this problem as it
doesn't use this function.

There are no known exploits available at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://curl.haxx.se/docs/adv_20130622.html"
  );
  # http://www.freebsd.org/ports/portaudit/01cf67b3-dc3b-11e2-a6cd-c48508086173.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?116f5a64"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"curl>=7.7<7.24.0_4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
