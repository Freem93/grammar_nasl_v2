#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2929. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74043);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/11 14:12:51 $");

  script_cve_id("CVE-2014-0081", "CVE-2014-0082", "CVE-2014-0130");
  script_bugtraq_id(65604, 65647, 67244);
  script_osvdb_id(103439, 106704);
  script_xref(name:"DSA", value:"2929");

  script_name(english:"Debian DSA-2929-1 : ruby-actionpack-3.2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Action Pack, a component of
Ruby on Rails.

  - CVE-2014-0081
    actionview/lib/action_view/helpers/number_helper.rb
    contains multiple cross-site scripting vulnerabilities

  - CVE-2014-0082
    actionpack/lib/action_view/template/text.rb performs
    symbol interning on MIME type strings, allowing remote
    denial-of-service attacks via increased memory
    consumption.

  - CVE-2014-0130
    A directory traversal vulnerability in
    actionpack/lib/abstract_controller/base.rb allows remote
    attackers to read arbitrary files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=747382"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0081"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0082"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0130"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ruby-actionpack-3.2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2929"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ruby-actionpack-3.2 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 3.2.6-6+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ruby-actionpack-3.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"ruby-actionpack-3.2", reference:"3.2.6-6+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
