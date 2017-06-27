#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2873. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72952);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:43 $");

  script_cve_id("CVE-2013-7345", "CVE-2014-2270");
  script_bugtraq_id(66002);
  script_osvdb_id(104081, 104208);
  script_xref(name:"DSA", value:"2873");

  script_name(english:"Debian DSA-2873-1 : file - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in file, a file type
classification tool.

Aaron Reffett reported a flaw in the way the file utility determined
the type of Portable Executable (PE) format files, the executable
format used on Windows. When processing a defective or intentionally
prepared PE executable which contains invalid offset information, the
file_strncmp routine will access memory that is out of bounds, causing
file to crash. The Common Vulnerabilities and Exposures project ID
CVE-2014-2270 has been assigned to identify this flaw.

Mike Frysinger reported that file's rule for detecting AWK scripts
significantly slows down file. The regular expression to detect AWK
files contained two star operators, which could be exploited to cause
excessive backtracking in the regex engine."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=703993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-2270"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/file"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/file"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2873"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the file packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 5.04-5+squeeze4.

For the stable distribution (wheezy), these problems have been fixed
in version 5.11-2+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:file");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/12");
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
if (deb_check(release:"6.0", prefix:"file", reference:"5.04-5+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libmagic-dev", reference:"5.04-5+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"libmagic1", reference:"5.04-5+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"python-magic", reference:"5.04-5+squeeze4")) flag++;
if (deb_check(release:"6.0", prefix:"python-magic-dbg", reference:"5.04-5+squeeze4")) flag++;
if (deb_check(release:"7.0", prefix:"file", reference:"5.11-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libmagic-dev", reference:"5.11-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libmagic1", reference:"5.11-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python-magic", reference:"5.11-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python-magic-dbg", reference:"5.11-2+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
