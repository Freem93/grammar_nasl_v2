#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2713. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66974);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/07/15 14:49:03 $");

  script_cve_id("CVE-2013-2174");
  script_osvdb_id(94519);
  script_xref(name:"DSA", value:"2713");

  script_name(english:"Debian DSA-2713-1 : curl - heap overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Timo Sirainen discovered that cURL, an URL transfer library, is prone
to a heap overflow vulnerability due to bad checking of the input data
in the curl_easy_unescape function.

The curl command line tool is not affected by this problem as it
doesn't use the curl_easy_unescape function."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2713"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the curl packages.

For the oldstable distribution (squeeze), this problem has been fixed
in version 7.21.0-2.1+squeeze4.

For the stable distribution (wheezy), this problem has been fixed in
version 7.26.0-1+wheezy3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"curl", reference:"7.21.0-2.1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl3", reference:"7.21.0-2.1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl3-dbg", reference:"7.21.0-2.1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl3-gnutls", reference:"7.21.0-2.1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl4-gnutls-dev", reference:"7.21.0-2.1+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl4-openssl-dev", reference:"7.21.0-2.1+squeeze4")) flag++;
if (deb_check(release:"7.0", prefix:"curl", reference:"7.26.0-1+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3", reference:"7.26.0-1+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-dbg", reference:"7.26.0-1+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-gnutls", reference:"7.26.0-1+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl3-nss", reference:"7.26.0-1+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-gnutls-dev", reference:"7.26.0-1+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-nss-dev", reference:"7.26.0-1+wheezy3")) flag++;
if (deb_check(release:"7.0", prefix:"libcurl4-openssl-dev", reference:"7.26.0-1+wheezy3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
