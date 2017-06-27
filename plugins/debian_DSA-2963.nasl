#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2963. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76091);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/16 15:48:47 $");

  script_cve_id("CVE-2013-6397", "CVE-2013-6407", "CVE-2013-6408");
  script_bugtraq_id(63935, 64008, 64009);
  script_xref(name:"DSA", value:"2963");

  script_name(english:"Debian DSA-2963-1 : lucene-solr - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in Solr, an open source enterprise
search server based on Lucene, resulting in information disclosure or
code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/lucene-solr"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2963"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lucene-solr packages.

For the stable distribution (wheezy), these problems have been fixed
in version 3.6.0+dfsg-1+deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lucene-solr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"liblucene3-contrib-java", reference:"3.6.0+dfsg-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"liblucene3-java", reference:"3.6.0+dfsg-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"liblucene3-java-doc", reference:"3.6.0+dfsg-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsolr-java", reference:"3.6.0+dfsg-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"solr-common", reference:"3.6.0+dfsg-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"solr-jetty", reference:"3.6.0+dfsg-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"solr-tomcat", reference:"3.6.0+dfsg-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
