#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-739-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95664);
  script_version("$Revision: 3.5 $");
  script_cvs_date("$Date: 2017/02/27 15:13:33 $");

  script_cve_id("CVE-2016-8654", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8882", "CVE-2016-8883", "CVE-2016-8887", "CVE-2016-9560");
  script_osvdb_id(143483, 143485, 145760, 145761, 145771, 147666, 147946);

  script_name(english:"Debian DLA-739-1 : jasper security updat");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2016-8691 FPE on unknown address ... jpc_dec_process_siz ...
jpc_dec.c

CVE-2016-8692 FPE on unknown address ... jpc_dec_process_siz ...
jpc_dec.c

CVE-2016-8693 attempting double-free ... mem_close ... jas_stream.c

CVE-2016-8882 segfault / NULL pointer access in jpc_pi_destroy

CVE-2016-9560 stack-based buffer overflow in jpc_tsfb_getbands2
(jpc_tsfb.c)

CVE-2016-8887 part 1 + 2 NULL pointer dereference in jp2_colr_destroy
(jp2_cod.c)

CVE-2016-8654 Heap-based buffer overflow in QMFB code in JPC codec

CVE-2016-8883 assert in jpc_dec_tiledecode()

TEMP-CVE heap-based buffer overflow in jpc_dec_tiledecode (jpc_dec.c)

For Debian 7 'Wheezy', these problems have been fixed in version
1.900.1-13+deb7u5.

We recommend that you upgrade your jasper packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/12/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/jasper"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjasper-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjasper-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjasper1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"7.0", prefix:"libjasper-dev", reference:"1.900.1-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libjasper-runtime", reference:"1.900.1-13+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libjasper1", reference:"1.900.1-13+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
