#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3561. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90808);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-2167", "CVE-2016-2168");
  script_osvdb_id(137779, 137780, 137803);
  script_xref(name:"DSA", value:"3561");

  script_name(english:"Debian DSA-3561-1 : subversion - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Subversion, a version
control system. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2016-2167
    Daniel Shahaf and James McCoy discovered that an
    implementation error in the authentication against the
    Cyrus SASL library would permit a remote user to specify
    a realm string which is a prefix of the expected realm
    string and potentially allowing a user to authenticate
    using the wrong realm.

  - CVE-2016-2168
    Ivan Zhakov of VisualSVN discovered a remotely
    triggerable denial of service vulnerability in the
    mod_authz_svn module during COPY or MOVE authorization
    check. An authenticated remote attacker could take
    advantage of this flaw to cause a denial of service
    (Subversion server crash) via COPY or MOVE requests with
    specially crafted header."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-2168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/subversion"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3561"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the subversion packages.

For the stable distribution (jessie), these problems have been fixed
in version 1.8.10-6+deb8u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:subversion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");
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
if (deb_check(release:"8.0", prefix:"libapache2-mod-svn", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libapache2-svn", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-dev", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-doc", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-java", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-perl", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn-ruby1.8", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"libsvn1", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"python-subversion", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"ruby-svn", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"subversion", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"subversion-dbg", reference:"1.8.10-6+deb8u4")) flag++;
if (deb_check(release:"8.0", prefix:"subversion-tools", reference:"1.8.10-6+deb8u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
