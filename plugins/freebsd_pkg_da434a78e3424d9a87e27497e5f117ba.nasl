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
  script_id(85730);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/09/18 13:38:30 $");

  script_cve_id("CVE-2015-3417");

  script_name(english:"FreeBSD : ffmpeg -- use-after-free (da434a78-e342-4d9a-87e2-7497e5f117ba)");
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
"NVD reports :

Use-after-free vulnerability in the ff_h264_free_tables function in
libavcodec/h264.c in FFmpeg before 2.3.6 allows remote attackers to
cause a denial of service or possibly have unspecified other impact
via crafted H.264 data in an MP4 file, as demonstrated by an HTML
VIDEO element that references H.264 data."
  );
  # https://git.videolan.org/?p=ffmpeg.git;a=commitdiff;h=e8714f6f93d1a32f4e4655209960afcf4c185214
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7bf68fa3"
  );
  # https://git.libav.org/?p=libav.git;a=commitdiff;h=3b69f245dbe6e2016659a45c4bfe284f6c5ac57e
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8aa9571d"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://ffmpeg.org/security.html"
  );
  # https://git.libav.org/?p=libav.git;a=blob;f=Changelog;hb=refs/tags/v11.4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d326e854"
  );
  # http://www.freebsd.org/ports/portaudit/da434a78-e342-4d9a-87e2-7497e5f117ba.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8ab52bc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg23");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:ffmpeg25");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:gstreamer1-libav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:handbrake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:libav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mythtv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:mythtv-frontend");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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

if (pkg_test(save_report:TRUE, pkg:"libav>=11.0<11.4")) flag++;
if (pkg_test(save_report:TRUE, pkg:"libav<10.7")) flag++;
if (pkg_test(save_report:TRUE, pkg:"gstreamer1-libav<1.5.0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"handbrake>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg>=2.2.0,1<2.2.12,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg>=2.1.0,1<2.1.7,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg<2.0.7,1")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg25<2.5.2")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg24<2.4.5")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg23<2.3.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"ffmpeg1<1.2.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mythtv>=0")) flag++;
if (pkg_test(save_report:TRUE, pkg:"mythtv-frontend>=0")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:pkg_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
