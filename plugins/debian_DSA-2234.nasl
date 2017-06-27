#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2234. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53861);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-0668", "CVE-2009-0669");
  script_bugtraq_id(35987);
  script_osvdb_id(56826, 56827);
  script_xref(name:"DSA", value:"2234");

  script_name(english:"Debian DSA-2234-1 : zodb - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in python-zodb, a
set of tools for using ZODB, that could lead to arbitrary code
execution in the worst case. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-0668
    The ZEO server doesn't restrict the callables when
    unpickling data received from a malicious client which
    can be used by an attacker to execute arbitrary Python
    code on the server by sending certain exception pickles.
    This also allows an attacker to import any importable
    module as ZEO is importing the module containing a
    callable specified in a pickle to test for a certain
    flag.

  - CVE-2009-0669
    Due to a programming error, an authorization method in
    the StorageServer component of ZEO was not used as an
    internal method. This allows a malicious client to
    bypass authentication when connecting to a ZEO server by
    simply calling this authorization method.

The update also limits the number of new object ids a client can
request to 100 as it would be possible to consume huge amounts of
resources by requesting a big batch of new object ids. No CVE id has
been assigned to this."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=540465"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2234"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the zodb packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:3.6.0-2+lenny3.

The stable distribution (squeeze) is not affected, it was fixed before
the initial release."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:zodb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"zodb", reference:"1:3.6.0-2+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
