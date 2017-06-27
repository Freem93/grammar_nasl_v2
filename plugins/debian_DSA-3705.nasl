#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3705. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94588);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/11/10 14:37:36 $");

  script_cve_id("CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624");
  script_osvdb_id(146565, 146567, 146568, 146569, 146570, 146571, 146572, 146573, 146574, 146575);
  script_xref(name:"DSA", value:"3705");

  script_name(english:"Debian DSA-3705-1 : curl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in cURL, an URL transfer
library :

  - CVE-2016-8615
    It was discovered that a malicious HTTP server could
    inject new cookies for arbitrary domains into a cookie
    jar.

  - CVE-2016-8616
    It was discovered that when re-using a connection, curl
    was doing case insensitive comparisons of user name and
    password with the existing connections.

  - CVE-2016-8617
    It was discovered that on systems with 32-bit addresses
    in userspace (e.g. x86, ARM, x32), the output buffer
    size value calculated in the base64 encode function
    would wrap around if input size was at least 1GB of
    data, causing an undersized output buffer to be
    allocated.

  - CVE-2016-8618
    It was discovered that the curl_maprintf() function
    could be tricked into doing a double-free due to an
    unsafe size_t multiplication on systems using 32 bit
    size_t variables.

  - CVE-2016-8619
    It was discovered that the Kerberos implementation could
    be tricked into doing a double-free when reading one of
    the length fields from a socket.

  - CVE-2016-8620
    It was discovered that the curl tool's 'globbing'
    feature could write to invalid memory areas when parsing
    invalid ranges.

  - CVE-2016-8621
    It was discovered that the function curl_getdate could
    read out of bounds when parsing invalid date strings.

  - CVE-2016-8622
    It was discovered that the URL percent-encoding decode
    function would return a signed 32bit integer variable as
    length, even though it allocated a destination buffer
    larger than 2GB, which would lead to a out-of-bounds
    write.

  - CVE-2016-8623
    It was discovered that libcurl could access an
    already-freed memory area due to concurrent access to
    shared cookies. This could lead to a denial of service
    or disclosure of sensitive information.

  - CVE-2016-8624
    It was discovered that curl wouldn't parse the authority
    component of a URL correctly when the host name part
    ends with a '#' character, and could be tricked into
    connecting to a different host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8621"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-8624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3705"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the curl packages.

For the stable distribution (jessie), these problems have been fixed
in version 7.38.0-4+deb8u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"curl", reference:"7.38.0-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3", reference:"7.38.0-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-dbg", reference:"7.38.0-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-gnutls", reference:"7.38.0-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl3-nss", reference:"7.38.0-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-doc", reference:"7.38.0-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-gnutls-dev", reference:"7.38.0-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-nss-dev", reference:"7.38.0-4+deb8u5")) flag++;
if (deb_check(release:"8.0", prefix:"libcurl4-openssl-dev", reference:"7.38.0-4+deb8u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
